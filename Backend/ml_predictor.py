"""
ML Predictor — loads best trained model and returns phishing probabilities.
"""
import os
import json

try:
    import joblib
except ImportError:
    joblib = None

try:
    import numpy as np
except ImportError:
    np = None


class MLPredictor:
    """
    Loads trained model & TF-IDF vectorizer.
    Auto-trains if model files are missing.
    """

    def __init__(self, model_path="ml_model.pkl",
                 vectorizer_path="tfidf_vectorizer.pkl",
                 metadata_path="ml_metadata.json"):
        self.model_path      = model_path
        self.vectorizer_path = vectorizer_path
        self.metadata_path   = metadata_path
        self.model      = None
        self.vectorizer = None
        self.model_name = "Unknown"
        self._load()

    # ------------------------------------------------------------------

    def _load(self):
        try:
            if joblib is None or np is None:
                print("⚠️  ML predictor unavailable because required packages are missing.")
                return

            if not (os.path.exists(self.model_path) and
                    os.path.exists(self.vectorizer_path)):
                print("⚠️  Model not found → training now…")
                try:
                    from ml_trainer import MLModelTrainer
                    MLModelTrainer(self.model_path, self.vectorizer_path,
                                   self.metadata_path).train(verbose=False)
                except Exception as inner_e:
                    print(f"❌ ML training unavailable: {inner_e}")
                    return

            self.model      = joblib.load(self.model_path)
            self.vectorizer = joblib.load(self.vectorizer_path)

            if os.path.exists(self.metadata_path):
                with open(self.metadata_path) as f:
                    meta = json.load(f)
                self.model_name = meta.get("best_model", "Unknown")
                self._metadata = meta
            else:
                self._metadata = {}

            print(f"✅ ML model ready ({self.model_name})")
        except Exception as e:
            print(f"❌ ML load error: {e}")

    # ------------------------------------------------------------------

    def predict(self, text: str) -> dict:
        """
        Returns:
          is_phishing  : bool
          confidence   : float 0-100 (probability of predicted class)
          phishing_prob: float 0-100 (probability of phishing class specifically)
          model_status : 'ready' | 'unavailable'
          model_name   : str
        """
        if self.model is None or self.vectorizer is None or joblib is None or np is None:
            return {"is_phishing": False, "confidence": 0,
                    "phishing_prob": 0.0, "model_status": "unavailable",
                    "model_name": "N/A"}
        try:
            vec  = self.vectorizer.transform([text])
            pred = int(self.model.predict(vec)[0])
            prob = self.model.predict_proba(vec)[0]   # [prob_safe, prob_phishing]

            phishing_prob = float(prob[1]) * 100
            confidence    = float(max(prob)) * 100

            return {
                "is_phishing":   bool(pred),
                "confidence":    round(confidence, 2),
                "phishing_prob": round(phishing_prob, 2),
                "model_status":  "ready",
                "model_name":    self.model_name,
            }
        except Exception as e:
            print(f"❌ Prediction error: {e}")
            return {"is_phishing": False, "confidence": 0,
                    "phishing_prob": 0.0, "model_status": "error",
                    "model_name": self.model_name}

    def get_top_features(self, text: str, n: int = 5) -> list:
        """
        Returns list of (word, weight) tuples that most influenced prediction.
        Works for Linear models; falls back gracefully for others.
        """
        if self.model is None or self.vectorizer is None or joblib is None or np is None:
            return []
        try:
            vec   = self.vectorizer.transform([text])
            names = self.vectorizer.get_feature_names_out()
            # LinearSVC / LogisticRegression have .coef_
            if hasattr(self.model, "coef_"):
                coef    = self.model.coef_[0]
                weights = vec.multiply(coef).toarray()[0]
            # NB has feature_log_prob_
            elif hasattr(self.model, "feature_log_prob_"):
                # difference between phishing and safe log-probs
                diff    = self.model.feature_log_prob_[1] - self.model.feature_log_prob_[0]
                weights = vec.multiply(diff).toarray()[0]
            else:
                return []

            top_idx = np.abs(weights).argsort()[-n:][::-1]
            return [(names[i], round(float(weights[i]), 4)) for i in top_idx
                    if weights[i] != 0]
        except Exception as e:
            print(f"❌ Feature extraction error: {e}")
            return []

    def get_model_metadata(self) -> dict:
        return getattr(self, "_metadata", {})


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    p = MLPredictor()
    email = "Urgent! Verify your account now http://fake-bank.xyz or it will be suspended"
    r = p.predict(email)
    print(f"Result : {r}")
    print(f"Features: {p.get_top_features(email)}")
