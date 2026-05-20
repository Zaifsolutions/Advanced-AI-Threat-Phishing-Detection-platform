"""
Phishing Explainer — combines heuristic + ML into human-readable output.
"""
from ml_predictor import MLPredictor


class PhishingExplainer:
    def __init__(self):
        self.ml_predictor = MLPredictor()

    def explain_analysis(self, email_text: str,
                         heuristic_result: dict,
                         url_risks: list = None) -> dict:
        ml  = self.ml_predictor.predict(email_text)
        features = self.ml_predictor.get_top_features(email_text, n=3)

        reasons = list(heuristic_result.get("reasons", []))

        if ml["model_status"] == "ready":
            if ml["is_phishing"]:
                reasons.append(
                    f"ML ({ml['model_name']}): {ml['phishing_prob']:.1f}% phishing probability"
                )
            else:
                reasons.append(
                    f"ML ({ml['model_name']}): {100 - ml['phishing_prob']:.1f}% safe probability"
                )
            if features:
                top = ", ".join(f"'{f[0]}'" for f in features[:2])
                reasons.append(f"Key influencing words: {top}")

        if url_risks:
            for ur in url_risks:
                if ur.get("risk_score", 0) > 50:
                    reasons.append(
                        f"Risky URL: {ur['url'][:60]}… → {ur['verdict']} (score {ur['risk_score']})"
                    )

        reasons = list(dict.fromkeys(reasons))   # deduplicate

        h_score  = heuristic_result.get("risk_score", 0)
        ml_prob  = ml.get("phishing_prob", 0) if ml["is_phishing"] else 0
        final    = min(100, int(0.6 * h_score + 0.4 * ml_prob))

        if final < 30:
            status = "Safe"
        elif final < 60:
            status = "Suspicious"
        else:
            status = "Phishing"

        return {
            "risk_score":        final,
            "status":            status,
            "reasons":           reasons,
            "keywords_found":    self._keywords(email_text),
            "ml_confidence":     round(ml["phishing_prob"], 1),
            "heuristic_score":   h_score,
            "model_status":      ml["model_status"],
            "top_ml_features":   [(f[0], round(f[1], 4)) for f in features],
        }

    def _keywords(self, text: str) -> list:
        kws = [
            "verify", "confirm", "urgent", "click here", "password", "account",
            "update", "suspended", "validate", "credentials", "immediate",
            "action required", "unusual activity", "secure", "banking",
            "paypal", "amazon", "apple", "microsoft", "invoice",
        ]
        lo = text.lower()
        return list(dict.fromkeys(k for k in kws if k in lo))
