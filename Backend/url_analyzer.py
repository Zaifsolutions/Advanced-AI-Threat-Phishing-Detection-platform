"""
Advanced URL Analyzer
Heuristic checks: typosquatting, suspicious TLDs, IP URLs, shorteners, etc.
"""
import re
from urllib.parse import urlparse, unquote
from difflib import SequenceMatcher


class URLAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            "login", "verify", "update", "secure", "account", "banking",
            "paypal", "auth", "signin", "confirm", "validate", "confirm-account",
            "verify-identity", "click-here", "urgent", "action", "confirm-now",
            "password", "credential", "recover", "suspend", "locked",
        ]
        self.known_safe_domains = {
            "amazon.com", "google.com", "microsoft.com", "apple.com",
            "facebook.com", "twitter.com", "github.com", "stackoverflow.com",
            "reddit.com", "youtube.com", "linkedin.com", "instagram.com",
            "paypal.com", "netflix.com", "dropbox.com", "spotify.com",
        }
        self.known_phishing_domains = {
            "amaz0n.com", "goggle.com", "microsft.com", "appel.com",
            "faceb00k.com", "paypa1.com", "appleid.com-secure.tk",
            "secure-paypal.com", "amazon-login.net", "apple-verify.com",
        }
        self.shortener_services = {
            "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "short.link",
            "bitly.com", "shortz.me", "shorturl.at", "tiny.cc",
            "t.co", "rb.gy", "cutt.ly", "is.gd", "buff.ly",
        }
        self.suspicious_tlds = {
            ".tk", ".ml", ".ga", ".cf", ".top", ".xyz", ".online", ".site",
            ".website", ".space", ".download", ".stream", ".review", ".click",
            ".loan", ".men", ".world", ".science", ".win", ".trade", ".bid",
            ".party", ".faith", ".date", ".racing",
        }
        self.legitimate_brands = [
            "amazon", "apple", "microsoft", "google", "paypal", "facebook",
            "twitter", "netflix", "dropbox", "instagram", "linkedin", "uber",
            "airbnb", "reddit", "pinterest", "spotify", "discord", "telegram",
            "whatsapp", "youtube", "ebay", "walmart", "chase", "wellsfargo",
        ]

    # ------------------------------------------------------------------

    def analyze(self, url: str) -> dict:
        reasons, risk = [], 0

        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().lstrip("www.")
            path   = unquote(parsed.path.lower())
            query  = unquote(parsed.query.lower())
        except Exception:
            return {
                "url": url, "risk_score": 50, "verdict": "Suspicious",
                "reasons": ["Could not parse URL — possibly malformed."],
                "domain": "", "typosquat_score": 0, "domain_age_days": -1,
            }

        # Strip port from domain for checks
        domain_clean = domain.split(":")[0]

        # 1 — IP address as host
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain_clean):
            risk += 40
            reasons.append("IP address used instead of domain name — HIGH RISK")

        # 2 — Known phishing domain
        if domain_clean in self.known_phishing_domains:
            risk += 60
            reasons.append(f"Domain '{domain_clean}' is in phishing blacklist")

        # 3 — Confirmed safe domain (reduce false positives)
        if domain_clean in self.known_safe_domains:
            return {
                "url": url, "risk_score": 0, "verdict": "Safe",
                "reasons": [f"'{domain_clean}' is a verified safe domain."],
                "domain": domain_clean, "typosquat_score": 0,
                "domain_age_days": -1,
            }

        # 4 — URL length
        if len(url) > 100:
            risk += 15
            reasons.append(f"Unusually long URL ({len(url)} chars) — may hide payload")

        # 5 — '@' in URL
        if "@" in url:
            risk += 50
            reasons.append("'@' symbol in URL — credential harvesting indicator")

        # 6 — Excessive subdomains
        dot_count = domain_clean.count(".")
        if dot_count > 3:
            risk += 20
            reasons.append(f"Excessive subdomains ({dot_count} dots) — common in phishing")

        # 7 — Suspicious keywords in domain/path/query
        combined = domain_clean + path + query
        for kw in self.suspicious_keywords:
            if kw in combined:
                risk += 15
                reasons.append(f"Suspicious keyword '{kw}' found in URL")
                break

        # 8 — Typosquatting
        typosquat_score, similar = self._detect_typosquatting(domain_clean)
        if typosquat_score > 0.70:
            risk += int(typosquat_score * 35)
            reasons.append(
                f"Typosquatting detected: '{domain_clean}' resembles '{similar}'"
            )

        # 9 — Suspicious TLD
        for tld in self.suspicious_tlds:
            if domain_clean.endswith(tld):
                risk += 15
                reasons.append(f"High-risk TLD '{tld}' commonly used in phishing")
                break

        # 10 — URL shortener
        for svc in self.shortener_services:
            if svc in domain_clean:
                risk += 20
                reasons.append(f"URL shortener '{svc}' — hides real destination")
                break

        # 11 — Non-standard port
        if ":" in domain:
            try:
                port = int(domain.split(":")[1])
                if port not in (80, 443, 8080, 8443):
                    risk += 15
                    reasons.append(f"Unusual port {port} detected")
            except Exception:
                pass

        # 12 — Hex / octal encoding
        if re.search(r"0x[0-9a-f]+|%[0-9a-f]{2}", url):
            count = url.count("%")
            if count > 3:
                risk += 15
                reasons.append("Excessive URL encoding — possible obfuscation")

        # 13 — Multiple hyphens in domain
        if domain_clean.count("-") > 2:
            risk += 10
            reasons.append("Multiple hyphens in domain — common in phishing URLs")

        # 14 — HTTP (not HTTPS)
        if url.startswith("http://") and not url.startswith("http://localhost"):
            risk += 10
            reasons.append("Non-secure HTTP connection (no TLS/SSL)")

        # 15 — Redirect chains in URL
        redirect_patterns = re.findall(r"url=|redirect=|redir=|return=", query)
        if redirect_patterns:
            risk += 20
            reasons.append("Open redirect parameters detected in URL")

        risk = min(risk, 100)
        
        # EVIDENCE-ONLY SCORING: If no indicators found, risk is truly 0
        # Do NOT artificially cap safe URLs
        if risk == 0:
            verdict = "Safe"
        elif risk < 60:
            verdict = "Suspicious"
        else:
            verdict = "Phishing"

        # Build reasons list - ONLY include if evidence exists
        if not reasons:
            if verdict == "Safe":
                reasons = ["URL analysis completed. No phishing indicators detected."]
            else:
                reasons = ["URL exhibits suspicious characteristics."]

        return {
            "url":             url,
            "risk_score":      risk,
            "verdict":         verdict,
            "reasons":         reasons,
            "domain":          domain_clean,
            "domain_age_days": -1,
            "typosquat_score": round(typosquat_score, 2),
        }

    # ------------------------------------------------------------------

    def _detect_typosquatting(self, domain: str) -> tuple[float, str]:
        base = domain.split(".")[0]
        best_score, best_brand = 0.0, ""
        for brand in self.legitimate_brands:
            s = SequenceMatcher(None, base, brand).ratio()
            if s > best_score and s > 0.70 and base != brand:
                best_score, best_brand = s, brand + ".com"
        return best_score, best_brand
