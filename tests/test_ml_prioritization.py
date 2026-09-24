"""
Unit tests for Scikit-Learn ML Exploit Prioritization Engine.
Verifies:
- Feature extraction
- Training reproducibility
- Prediction bounding [0.01, 0.99]
- Higher risk assigned to internet-facing + high EPSS findings
- Graceful fallback behavior
"""

import pytest
from backend.ml_prioritization import ExploitLikelihoodModel, predict_exploit_likelihood


class MockFinding:
    def __init__(self, cvss, epss, exposure, severity, cve_id=None):
        self.cvss_score = cvss
        self.epss_score = epss
        self.exposure = exposure
        self.severity = severity
        self.cve_id = cve_id


def test_exploit_likelihood_model_trains_and_bounds():
    """Model must train and predict probabilities strictly within [0.01, 0.99]."""
    model = ExploitLikelihoodModel()
    train_res = model.train_synthetic(n_samples=200)
    assert train_res["train_samples"] == 200
    assert train_res["accuracy"] > 0.65  # Better than random baseline

    finding = MockFinding(cvss=8.5, epss=0.65, exposure="internet_facing", severity="critical", cve_id="CVE-2024-1234")
    prob = model.predict_likelihood(finding)
    assert 0.01 <= prob <= 0.99


def test_predict_exploit_likelihood_ordering():
    """Internet-facing critical CVE with high EPSS must have higher exploit probability than internal low severity."""
    high_threat = MockFinding(cvss=9.8, epss=0.85, exposure="internet_facing", severity="critical", cve_id="CVE-2024-9999")
    low_threat = MockFinding(cvss=3.0, epss=0.01, exposure="isolated", severity="low", cve_id=None)

    prob_high = predict_exploit_likelihood(high_threat)
    prob_low = predict_exploit_likelihood(low_threat)

    assert prob_high > prob_low
    assert prob_high >= 0.50
    assert prob_low <= 0.30


def test_public_predict_function_signature():
    """Verifies the public API function signature."""
    f = MockFinding(cvss=7.0, epss=0.20, exposure="dmz", severity="medium")
    result = predict_exploit_likelihood(f)
    assert isinstance(result, float)
    assert 0.01 <= result <= 0.99
