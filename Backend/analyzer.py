"""
Advanced Text / Email Analyzer
Hybrid: Heuristic rule engine + ML model (60/40 weighted).
"""
import re
from utils import sanitize_text
from ml_predictor import MLPredictor


class TextAnalyzer:
    def __init__(self):
        # ── Urgency / Social Engineering ──────────────────────────────
        self.urgent_words = [
            "urgent", "immediate action required", "suspended", "verify your account",
            "password expire", "act now", "confirm immediately", "hurry", "asap",
            "click here", "verify account", "validate identity", "confirm details",
            "time-sensitive", "limited time", "deadline", "final notice", "last chance",
            "respond immediately", "account locked", "access restricted",
        ]

        # ── Financial Scam ────────────────────────────────────────────
        self.financial_words = [
            "invoice", "payment", "bank", "transfer", "crypto", "wallet",
            "credit card", "debit card", "wire transfer", "billing", "charge",
            "refund", "transaction", "amount", "balance", "account suspended",
            "wire funds", "bitcoin", "ethereum", "gift card", "western union",
        ]

        # ── Credential Harvesting ─────────────────────────────────────
        self.credential_words = [
            "password", "ssn", "credentials", "username", "login", "pin",
            "two-factor", "2fa", "authentication", "secret", "security code",
            "cvv", "social security", "driver license", "passport",
            "mother maiden name", "date of birth", "verify account",
            "verify your account", "account verification",
        ]

        # ── Brand Impersonation ───────────────────────────────────────
        self.impersonation_words = [
            "amazon", "apple", "microsoft", "google", "paypal", "bank",
            "irs", "social security", "netflix", "uber", "facebook", "twitter",
            "instagram", "whatsapp", "telegram", "spotify", "dropbox",
            "fedex", "dhl", "ups", "usps", "hsbc", "wells fargo", "chase",
        ]

        # ── Advanced Scam Phrases (regex) ─────────────────────────────
        self.scam_phrases = [
            (r"you have won|congratulations you won",           "Prize scam"),
            (r"claim your reward|collect your prize",           "Prize scam"),
            (r"verify payment method|update billing",           "Payment scam"),
            (r"confirm your identity|verify identity",          "Identity theft"),
            (r"re-?activate account|reactivate account",        "Account takeover"),
            (r"unusual activity|suspicious activity detected",  "Social engineering"),
            (r"locked account|frozen account|suspended account","Account threat"),
            (r"take action now|act immediately|respond quickly","Urgency tactic"),
            (r"click this link|click here|click here now|open this link",  "Phishing link"),
            (r"verify your account|verify account|account verification",  "Phishing link"),
            (r"congratulations.*lucky winner",                  "Lottery scam"),
            (r"nigerian prince|inheritance.*claim",             "Advance-fee fraud"),
            (r"free gift|you.re selected|exclusive offer",      "Free gift scam"),
        ]

        # ── Ransomware / Malware Indicators ──────────────────────────
        self.malware_indicators = [
            "ransomware", "pay now", "your files", "encrypted", "decrypt",
            "restore", "recovery key", "payment proof", "bitcoin address",
            "tor browser", "onion link",
        ]

        # ── ML Predictor ──────────────────────────────────────────────
        try:
            self.ml_predictor  = MLPredictor()
            self.ml_available  = self.ml_predictor.model is not None
        except Exception:
            self.ml_predictor = None
            self.ml_available = False

    # ------------------------------------------------------------------

    def analyze_text(self, text: str) -> dict:
        if not text or not text.strip():
            return self._empty_result()

        clean = sanitize_text(text).lower()
        score = 0
        reasons, keywords = [], []

        # ── Heuristic checks ──────────────────────────────────────────

        # 1 — Urgency
        for w in self.urgent_words:
            if w in clean:
                score += 25; keywords.append(w)
                reasons.append(f"Urgent language detected: '{w}' (social engineering)")
                break

        # 2 — Financial
        for w in self.financial_words:
            if w in clean:
                score += 15; keywords.append(w)
                reasons.append(f"Financial keyword: '{w}'")
                break

        # 3 — Credentials
        for w in self.credential_words:
            if w in clean:
                score += 30; keywords.append(w)
                reasons.append(f"Sensitive info requested: '{w}' ⚠️ HIGH RISK")
                break

        # 4 — Brand impersonation
        for w in self.impersonation_words:
            if w in clean:
                score += 20; keywords.append(w)
                reasons.append(f"Possible brand impersonation: '{w}'")
                break

        # 5 — Scam phrases
        for pattern, label in self.scam_phrases:
            try:
                if re.search(pattern, clean, re.IGNORECASE):
                    score += 20
                    reasons.append(f"Scam pattern — {label}: '{pattern[:45]}'")
                    break
            except Exception:
                pass

        # 6 — Ransomware / malware
        for ind in self.malware_indicators:
            if ind in clean:
                score += 25; keywords.append(ind)
                reasons.append(f"🚨 Ransomware/Malware indicator: '{ind}'")
                break

        # 7 — Multiple URLs
        url_count = len(re.findall(r"https?://|www\.", clean))
        if url_count > 2:
            score += 10
            reasons.append(f"Multiple URLs in message ({url_count}) — suspicious pattern")

        # 8 — URL shorteners
        if re.search(r"bit\.ly|tinyurl|goo\.gl|ow\.ly|short\.link|t\.co", clean):
            score += 15; keywords.append("url-shortener")
            reasons.append("URL shortener detected (commonly used in phishing)")

        # 8.5 — Suspicious URL / TLD patterns in text
        suspicious_url = re.search(r"https?://[^\s]+|www\.[^\s]+", clean)
        if suspicious_url and re.search(r"\.tk|\.top|\.xyz|\.win|fake-|secure-|login|verify-account", suspicious_url.group(0)):
            score += 20
            reasons.append("Suspicious URL pattern detected in message")

        # 9 — Excessive punctuation / CAPS (spam heuristic)
        cap_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        if cap_ratio > 0.35:
            score += 10
            reasons.append("Excessive uppercase text (spam / urgency tactic)")

        # 10 — Mismatched "from" name vs domain pattern
        from_domain = re.search(r"from:.*?<.*?@([\w.-]+)>", clean)
        if from_domain:
            dom = from_domain.group(1)
            for brand in ["amazon", "paypal", "apple", "google", "microsoft"]:
                if brand in clean and brand not in dom:
                    score += 20
                    reasons.append(f"Sender domain mismatch — claims to be '{brand}' but domain is '{dom}'")
                    break

        # Cap heuristic score (never exceed 100)
        score = min(score, 100)
        
        # CRITICAL: If no indicators found, keep score at 0 (not defaulted to fake value)
        # This ensures safe files stay safe

        # ── ML prediction ─────────────────────────────────────────────
        # ONLY include ML if: (1) model is ready AND (2) heuristic score > 0
        # This prevents fake positives from ML on safe content
        ml_confidence = 0.0
        ml_phishing   = False
        ml_features   = []
        model_name    = "N/A"
        ml_ready = False

        if self.ml_available and self.ml_predictor and score > 0:
            r = self.ml_predictor.predict(text)
            if r["model_status"] == "ready":
                ml_ready = True
                ml_confidence = r["phishing_prob"]
                ml_phishing   = r["is_phishing"]
                model_name    = r["model_name"]
                ml_features   = self.ml_predictor.get_top_features(text, n=3)

                # ONLY report ML if it's highly confident (>70%)
                if ml_phishing and ml_confidence > 70:
                    reasons.append(
                        f"ML ({model_name}): {ml_confidence:.1f}% phishing probability"
                    )
                    if ml_features:
                        top_words = ", ".join(f"'{f[0]}'" for f in ml_features[:2])
                        reasons.append(f"Key ML features: {top_words}")

        # ── EVIDENCE-ONLY SCORING (NO DEFAULTS, NO GUESSING) ──────────
        # Start at 0, only add score if evidence exists
        if score == 0 and ml_confidence < 30:
            # No heuristic evidence AND no ML signal = SAFE (0%)
            final = 0
        elif score > 0 and ml_ready and ml_phishing and ml_confidence > 70:
            # Heuristic + high-confidence ML = boost score
            final = min(int(0.7 * score + 0.3 * ml_confidence), 100)
        else:
            # Heuristic alone OR low ML confidence = use heuristic only
            final = score
        
        final = min(final, 100)

        # ── Status ───────────────────────────────────────────────────
        if final < 30:
            status = "Safe"
        elif final < 60:
            status = "Suspicious"
        else:
            status = "Phishing"

        # ── Only add reasons if there's actual evidence ───────────────
        if not reasons:
            if final == 0:
                reasons = ["No phishing indicators detected — content appears safe."]
            else:
                reasons = ["Analysis complete — no additional threats detected."]
        
        # ── Generate detailed reason paragraph ──────────────────────
        reason_paragraph = self._generate_reason_paragraph(status, final, reasons, keywords)
        
        # ── Confidence level ───────────────────────────────────────
        confidence_level = self._get_confidence_level(final, ml_confidence if self.ml_available else 0)

        return {
            "risk_score":      final,
            "status":          status,
            "reasons":         reasons,
            "reason_paragraph": reason_paragraph,
            "confidence":      confidence_level,
            "keywords_found":  list(dict.fromkeys(keywords)),
            "ml_confidence":   round(ml_confidence, 1),
            "ml_phishing_prob": round(ml_confidence, 1),
            "heuristic_score": score,
            "ml_available":    self.ml_available,
            "model_name":      model_name,
            "top_ml_features": [(f[0], round(f[1], 4)) for f in ml_features],
        }

    # ------------------------------------------------------------------
    
    def _generate_reason_paragraph(self, status, score, reasons, keywords):
        """Generate a paragraph-style explanation ONLY based on actual evidence."""
        if status == "Safe":
            # Explain why safe - list what WAS NOT found
            not_found = []
            if not keywords:
                not_found.append("no phishing keywords")
            if score == 0:
                not_found.append("no suspicious patterns")
                not_found.append("no malware indicators")
            
            details = ", ".join(not_found) if not_found else "comprehensive analysis"
            return f"Full analysis completed with {details}. This content is classified as SAFE and presents no known phishing, malware, or social engineering threats. It is safe to interact with this content."
        
        elif status == "Suspicious":
            # Only explain based on actual detected evidence
            top_reasons = [r.replace("⚠️", "").replace("🚨", "").strip() for r in reasons[:2] if r]
            if top_reasons:
                reason_text = " ".join(top_reasons)
                return f"This content exhibits suspicious characteristics: {reason_text}. Exercise caution and verify the source before taking action. Do NOT provide personal information unless you can independently confirm the sender."
            else:
                return "This content was classified as suspicious based on analysis patterns. Verify the source before interacting."
        
        else:  # Phishing
            # Explain based ONLY on detected phishing indicators
            top_reasons = [r.replace("⚠️", "").replace("🚨", "").strip() for r in reasons[:3] if r]
            if top_reasons:
                reason_text = " ".join(top_reasons)
                return f"🚨 HIGH RISK: Multiple phishing indicators detected: {reason_text}. This appears to be a phishing attempt designed to steal sensitive information or credentials. DO NOT click links, download files, or provide any personal or financial information."
            else:
                return "🚨 HIGH RISK: This content is classified as phishing. Do not interact with it."
    
    def _get_confidence_level(self, risk_score, ml_conf):
        """Get confidence level based on evidence strength (no fake confidence)."""
        # ONLY report high confidence if we have multiple evidence types
        if risk_score >= 80:
            return "Very High"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 30:
            return "Medium"
        else:
            return "Low"

    # ------------------------------------------------------------------

    def _empty_result(self):
        return {
            "risk_score": 0, "status": "Safe",
            "reasons": ["No content provided for analysis."],
            "reason_paragraph": "No content was submitted for analysis. Please provide text, a file, URL, or audio to analyze.",
            "confidence": "Low",
            "keywords_found": [], "ml_confidence": 0,
            "ml_phishing_prob": 0, "heuristic_score": 0,
            "ml_available": self.ml_available, "model_name": "N/A",
            "top_ml_features": [],
        }
