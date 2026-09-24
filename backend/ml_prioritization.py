"""
CyberGuard AI - Machine Learning Exploit Prioritization Engine
Implements a Scikit-Learn Logistic Regression model to predict exploit probability.
Features: CVSS Score, EPSS Score, Exposure, Severity level, CVE presence.
"""

import os
from typing import Any, Dict, List, Tuple
import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from backend.config import settings


class ExploitLikelihoodModel:
    """
    Scikit-Learn Logistic Regression model for predicting the probability (0.0 to 1.0)
    that a vulnerability or misconfiguration will be actively exploited.
    """

    def __init__(self, model_path: str = settings.ML_MODEL_PATH):
        self.model_path = model_path
        self.model: LogisticRegression | None = None
        self.scaler: StandardScaler | None = None
        self._ensure_model_loaded()

    def _extract_features(self, item: Any) -> np.ndarray:
        """
        Extract numerical feature vector:
        1. cvss_score (float, 0.0 - 10.0)
        2. epss_score (float, 0.0 - 1.0)
        3. is_internet_facing (binary 0 or 1)
        4. severity_level (1: low, 2: medium, 3: high, 4: critical)
        5. has_cve (binary 0 or 1)
        """
        cvss = float(getattr(item, "cvss_score", 5.0) or 5.0)
        epss = float(getattr(item, "epss_score", 0.05) or 0.05)

        exposure = str(getattr(item, "exposure", "")).lower()
        if not exposure and hasattr(item, "exposure_factor"):
            exposure_factor = float(getattr(item, "exposure_factor", 0.5) or 0.5)
            is_internet = 1.0 if exposure_factor >= 0.9 else 0.0
        else:
            is_internet = 1.0 if "internet" in exposure else 0.0

        severity_str = str(getattr(item, "severity", "medium")).lower()
        sev_map = {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}
        severity_level = sev_map.get(severity_str, 2.0)

        cve = getattr(item, "cve_id", None)
        has_cve = 1.0 if cve and str(cve).startswith("CVE-") else 0.0

        return np.array([cvss, epss, is_internet, severity_level, has_cve], dtype=float)

    def train_synthetic(self, n_samples: int = 500) -> Dict[str, float]:
        """
        Train the logistic regression classifier on reproducible synthetic ground truth data.
        Target: 1 if exploited in the wild, 0 otherwise.
        """
        rng = np.random.default_rng(settings.RANDOM_SEED)

        # Synthetic feature generation
        cvss = rng.uniform(2.0, 10.0, n_samples)
        epss = rng.beta(0.5, 4.0, n_samples)  # Right-skewed distribution
        is_internet = rng.binomial(1, 0.35, n_samples)
        severity = rng.choice([1.0, 2.0, 3.0, 4.0], size=n_samples, p=[0.15, 0.35, 0.35, 0.15])
        has_cve = rng.binomial(1, 0.85, n_samples)

        X = np.column_stack([cvss, epss, is_internet, severity, has_cve])

        # Ground truth probability logit: strong correlation with EPSS, internet exposure, and CVSS
        logits = (
            -3.2
            + 0.35 * cvss
            + 4.50 * epss
            + 1.80 * is_internet
            + 0.50 * severity
            + 0.40 * has_cve
        )
        probs = 1.0 / (1.0 + np.exp(-logits))
        y = rng.binomial(1, probs)

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = LogisticRegression(random_state=settings.RANDOM_SEED, max_iter=200)
        self.model.fit(X_scaled, y)

        train_acc = float(self.model.score(X_scaled, y))

        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({"model": self.model, "scaler": self.scaler}, self.model_path)

        return {"train_samples": n_samples, "accuracy": round(train_acc, 4)}

    def _ensure_model_loaded(self) -> None:
        """Load trained model from disk or train if missing."""
        if os.path.exists(self.model_path):
            try:
                data = joblib.load(self.model_path)
                self.model = data["model"]
                self.scaler = data["scaler"]
                return
            except Exception:
                pass
        self.train_synthetic()

    def predict_likelihood(self, item: Any) -> float:
        """
        Predict exploit probability for a finding.
        Returns a float in [0.01, 0.99].
        """
        try:
            if self.model is None or self.scaler is None:
                self._ensure_model_loaded()

            features = self._extract_features(item).reshape(1, -1)
            features_scaled = self.scaler.transform(features)
            prob = float(self.model.predict_proba(features_scaled)[0, 1])
            return round(max(0.01, min(0.99, prob)), 4)
        except Exception:
            # Deterministic fallback if ML inference encounters unexpected error
            epss = float(getattr(item, "epss_score", 0.05) or 0.05)
            cvss = float(getattr(item, "cvss_score", 5.0) or 5.0)
            fallback = 0.65 * epss + 0.35 * (cvss / 10.0)
            return round(max(0.01, min(0.99, fallback)), 4)


# Singleton model instance
_model_instance = ExploitLikelihoodModel()


def predict_exploit_likelihood(finding: Any) -> float:
    """
    Public API to predict exploit likelihood.
    Matches required function signature:
        def predict_exploit_likelihood(finding: [FindingType]) -> float:
    """
    return _model_instance.predict_likelihood(finding)
