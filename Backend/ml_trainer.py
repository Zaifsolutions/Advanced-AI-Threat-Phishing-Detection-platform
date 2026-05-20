"""
Advanced ML Model Trainer - Multi-Model Pipeline
Trains Naive Bayes, Logistic Regression, and Random Forest.
Selects best model via cross-validation and saves it.
"""
import os
import json
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, classification_report)
from sklearn.model_selection import cross_val_score, StratifiedKFold
from dataset import PhishingDataset


class MLModelTrainer:
    """
    Trains multiple ML models and selects the best one.
    Saves model, vectorizer, and metadata for inference.
    """

    def __init__(self, model_path="ml_model.pkl", vectorizer_path="tfidf_vectorizer.pkl",
                 metadata_path="ml_metadata.json"):
        self.model_path = model_path
        self.vectorizer_path = vectorizer_path
        self.metadata_path = metadata_path
        self.model = None
        self.vectorizer = None
        self.best_model_name = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def train(self, verbose=True):
        """Train all models, pick the best, save artefacts."""
        if verbose:
            print("🚀 Starting Advanced ML training pipeline...")

        # --- 1. Load dataset ---
        dataset = PhishingDataset()
        X_train, X_test, y_train, y_test = dataset.get_train_test_split()
        if verbose:
            print(f"📦 Dataset: {len(X_train)} train / {len(X_test)} test samples")

        # --- 2. TF-IDF Vectorisation ---
        if verbose:
            print("📊 Building TF-IDF vectorizer (n-grams 1-2, 8 000 features)…")
        self.vectorizer = TfidfVectorizer(
            max_features=8000,
            stop_words="english",
            ngram_range=(1, 2),
            min_df=1,
            max_df=0.95,
            sublinear_tf=True,
        )
        X_train_tfidf = self.vectorizer.fit_transform(X_train)
        X_test_tfidf  = self.vectorizer.transform(X_test)
        if verbose:
            print(f"✅ TF-IDF ready: {X_train_tfidf.shape[1]} features")

        # --- 3. Define candidates ---
        candidates = {
            "Naive Bayes": MultinomialNB(alpha=0.5),
            "Logistic Regression": LogisticRegression(
                max_iter=2000, random_state=42, C=2.0,
                solver="lbfgs", class_weight="balanced"
            ),
            "Random Forest": RandomForestClassifier(
                n_estimators=100, random_state=42, n_jobs=-1,
                max_depth=20, class_weight="balanced"
            ),
        }

        # --- 4. Cross-validation ---
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_results = {}
        if verbose:
            print("\n🔬 Cross-validating all models (5-fold)…")
        for name, clf in candidates.items():
            scores = cross_val_score(clf, X_train_tfidf, y_train,
                                     cv=cv, scoring="f1", n_jobs=-1)
            cv_results[name] = scores.mean()
            if verbose:
                print(f"   {name:25s} → F1 = {scores.mean():.4f} ± {scores.std():.4f}")

        # --- 5. Pick best model ---
        self.best_model_name = max(cv_results, key=cv_results.get)
        if verbose:
            print(f"\n🏆 Best model: {self.best_model_name}")

        # --- 6. Train best on full training set ---
        self.model = candidates[self.best_model_name]
        self.model.fit(X_train_tfidf, y_train)

        # --- 7. Evaluate on held-out test set ---
        y_pred = self.model.predict(X_test_tfidf)
        metrics = {
            "accuracy":  float(accuracy_score(y_test, y_pred)),
            "precision": float(precision_score(y_test, y_pred, zero_division=0)),
            "recall":    float(recall_score(y_test, y_pred, zero_division=0)),
            "f1_score":  float(f1_score(y_test, y_pred, zero_division=0)),
            "best_model": self.best_model_name,
            "cv_results": {k: round(v, 4) for k, v in cv_results.items()},
        }
        if verbose:
            print("\n📈 Test-set performance:")
            for k, v in metrics.items():
                if k not in ("best_model", "cv_results"):
                    print(f"   • {k.capitalize():12s}: {v:.2%}")

        # --- 8. Save artefacts ---
        self._save_model(metrics)
        return metrics

    def load_model(self):
        """Load pre-trained model and vectorizer."""
        if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
            self.model = joblib.load(self.model_path)
            self.vectorizer = joblib.load(self.vectorizer_path)
            if os.path.exists(self.metadata_path):
                with open(self.metadata_path) as f:
                    meta = json.load(f)
                self.best_model_name = meta.get("best_model", "Unknown")
            print(f"✅ Model loaded: {self.best_model_name}")
            return True
        print("⚠️  Model files not found. Training new model…")
        self.train()
        return False

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _save_model(self, metadata: dict):
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.vectorizer, self.vectorizer_path)
        with open(self.metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        print(f"\n💾 Saved: {self.model_path}, {self.vectorizer_path}, {self.metadata_path}")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    trainer = MLModelTrainer()
    metrics = trainer.train(verbose=True)
    print(f"\n✅ Training complete — best model: {metrics['best_model']}")
