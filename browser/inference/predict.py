"""
predict.py
───────────
Runs every URL in a normalized browser case through the phishing detection
pipeline (feature_extractor.py → model.pkl) and returns per-URL predictions.

Two-layer detection:
    Layer 1 — pre_check()  : rule-based fast path (trusted domains, suspicious
                              TLDs, raw IPs, URL shorteners, etc.)
    Layer 2 — ML model     : RandomForestClassifier on 10 URL features

Extra metadata enrichment:
    - is_login_url   → password was saved here (automatic HIGH RISK escalation)
    - is_download_url→ file was downloaded from here (risk level raised)
    - visit_count    → context for reporting

Usage:
    from inference.predict import predict_browser_case
    results = predict_browser_case(normalized, model_path, extractor_path)
"""

from __future__ import annotations
import os
import sys
import importlib.util
from typing import Any

import joblib
import numpy as np


def _load_feature_extractor(extractor_path: str):
    """Dynamically load feature_extractor.py from any path."""
    spec = importlib.util.spec_from_file_location("feature_extractor", extractor_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _risk_level(prediction: str, confidence: float, is_login: bool, is_download: bool) -> str:
    if prediction == "benign":
        return "LOW"
    if is_login:
        return "HIGH"
    if confidence >= 0.85 or is_download:
        return "HIGH"
    if confidence >= 0.65:
        return "MEDIUM"
    return "LOW"


def predict_url(
    url: str,
    extractor,
    model,
    is_login_url: bool = False,
    is_download_url: bool = False,
    visit_count: int = 0,
) -> dict[str, Any]:
    """Run a single URL through Layer 1 (rules) then Layer 2 (ML) if needed."""
    # ── Layer 1: rule-based pre_check ────────────────────────────────
    override = extractor.pre_check(url)
    if override and override.get("override"):
        prediction = override["prediction"]
        confidence = override["confidence"]
        reason     = override["reason"]
        layer      = "rule"
    else:
        # ── Layer 2: ML model ─────────────────────────────────────────
        features = extractor.extract_features(url)
        X = np.array([features])
        proba = model.predict_proba(X)[0]   # [P(benign), P(phishing)]
        phishing_prob = float(proba[1])
        benign_prob   = float(proba[0])

        if phishing_prob >= 0.5:
            prediction = "phishing"
            confidence = phishing_prob
            reason     = f"ML model: {phishing_prob*100:.1f}% phishing probability"
        else:
            prediction = "benign"
            confidence = benign_prob
            reason     = f"ML model: {benign_prob*100:.1f}% benign probability"
        layer = "ml"

    if is_login_url and prediction == "benign":
        reason += " [NOTE: password saved here — verify manually]"

    risk = _risk_level(prediction, confidence, is_login_url, is_download_url)

    return {
        "url":             url,
        "prediction":      prediction,
        "confidence":      round(confidence, 4),
        "risk_level":      risk,
        "reason":          reason,
        "layer":           layer,
        "is_login_url":    is_login_url,
        "is_download_url": is_download_url,
        "visit_count":     visit_count,
    }


def predict_browser_case(
    normalized: dict[str, Any],
    model_path: str,
    extractor_path: str,
) -> dict[str, Any]:
    """
    Run predictions on all URLs in a normalized browser case.

    Parameters
    ----------
    normalized     : output of browser_normalizer.normalize_browser_case()
    model_path     : path to model.pkl (RandomForestClassifier)
    extractor_path : path to feature_extractor.py

    Returns
    -------
    dict with summary, predictions (sorted HIGH first), high_risk_urls
    """
    model     = joblib.load(model_path)
    extractor = _load_feature_extractor(extractor_path)

    predictions = []
    for url_entry in normalized["urls"]:
        result = predict_url(
            url             = url_entry["url"],
            extractor       = extractor,
            model           = model,
            is_login_url    = url_entry.get("is_login_url", False),
            is_download_url = url_entry.get("is_download_url", False),
            visit_count     = url_entry.get("visit_count", 0),
        )
        result["title"]   = url_entry.get("title", "")
        result["sources"] = url_entry.get("sources", [])
        predictions.append(result)

    # Sort: HIGH risk first, then confidence descending
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    predictions.sort(key=lambda x: (risk_order[x["risk_level"]], -x["confidence"]))

    phishing_preds = [p for p in predictions if p["prediction"] == "phishing"]
    high_risk      = [p for p in predictions if p["risk_level"] == "HIGH"]

    summary = {
        "total_urls":           len(predictions),
        "phishing_count":       len(phishing_preds),
        "benign_count":         len(predictions) - len(phishing_preds),
        "high_risk_count":      len(high_risk),
        "login_phishing_count": sum(1 for p in phishing_preds if p["is_login_url"]),
        "phishing_rate":        round(len(phishing_preds) / len(predictions) * 100, 1) if predictions else 0,
    }

    return {
        "case_id":        normalized["case_id"],
        "source_file":    normalized["source_file"],
        "category":       "browser",
        "summary":        summary,
        "predictions":    predictions,
        "high_risk_urls": high_risk,
    }


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from normalization.browser_normalizer import normalize_browser_case
    import json

    # Quick self-test
    BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print(f"[+] Model path     : {os.path.join(BASE, 'model', 'model.pkl')}")
    print(f"[+] Extractor path : {os.path.join(BASE, 'feature_extraction', 'feature_extractor.py')}")
    print("[+] predict.py loaded successfully — call predict_browser_case() to run inference.")
