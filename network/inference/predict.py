"""
predict.py — Network Inference (Isolation Forest)
────────────────────────────────────────────────────
Loads the trained Isolation Forest + scaler and scores NEW network traffic
(a raw per-packet tshark CSV, produced by the command in
feature_extraction/tshark_flow_fields.py) against the learned "normal
traffic" baseline.

INPUT REQUIRED: the raw per-packet tshark CSV — NOT the human-readable
tshark report text used by normalization/network_normalizer.py. Those are
two separate paths (see note in feature_extraction/tshark_flow_fields.py):
    - network_normalizer.py  -> rule-based indicators/events (from report text)
    - predict.py (this file) -> ML anomaly scoring (from raw per-packet CSV)

Get the raw CSV by running:
    tshark -r <pcap> -T fields \\
        -e frame.time_epoch -e ip.src -e ip.dst \\
        -e tcp.srcport -e tcp.dstport -e frame.len \\
        -e tcp.flags.syn -e tcp.flags.reset -e tcp.flags.push -e tcp.flags.ack \\
        -E separator=,

Model mechanics (Isolation Forest, unsupervised — different from the
Random Forest used in malware/browser):
    model.predict(X)         -> -1 (anomaly) or 1 (normal), NOT a probability
    model.decision_function(X) -> higher = more normal, lower/negative = more anomalous
We convert decision_function into a 0-1 "anomaly_score" (higher = more
anomalous) using a simple linear-clip heuristic, since Isolation Forest has
no native probability output. This threshold is a starting point — tune it
once you see the score distribution on real malicious vs. benign PCAPs.

Usage:
    from feature_extraction.tshark_flow_fields import build_flows
    from inference.predict import predict_network_case

    result = predict_network_case(
        raw_tshark_csv_text=open("flow_fields.csv").read(),
        case_id="case_001",
        source_file="malicious_network_traffic.pcap",
    )
"""

from __future__ import annotations
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

import joblib
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from feature_extraction.tshark_flow_fields import build_flows
from feature_extraction.feature_extractor import extract_features_for_flow, FEATURE_NAMES

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

DEFAULT_MODEL_PATH = os.path.join(MODELS_DIR, "network_isolation_forest.pkl")
DEFAULT_SCALER_PATH = os.path.join(MODELS_DIR, "network_scaler.pkl")
DEFAULT_COLUMNS_PATH = os.path.join(MODELS_DIR, "feature_columns.json")

# Heuristic clip range for converting decision_function -> 0-1 anomaly_score.
# decision_function scores from sklearn's IsolationForest typically fall
# roughly in [-0.5, 0.5]. Adjust these bounds once you've seen the real
# score distribution printed by train_baseline.py's validation step
# (Val score min / Val score max).
_SCORE_CLIP_LOW = -0.30   # decision_function value treated as anomaly_score = 1.0
_SCORE_CLIP_HIGH = 0.30   # decision_function value treated as anomaly_score = 0.0


def _load_artifacts(model_path: str, scaler_path: str, columns_path: str):
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    with open(columns_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    expected_features = meta.get("feature_names", FEATURE_NAMES)
    if expected_features != FEATURE_NAMES:
        # Defensive check: catches silent drift if feature_extractor.py's
        # FEATURE_NAMES ever gets reordered/changed without retraining.
        raise ValueError(
            "feature_columns.json order does not match feature_extractor.FEATURE_NAMES — "
            "the model was trained on a different feature order than this code computes. "
            "Retrain or fix FEATURE_NAMES before trusting predictions."
        )
    return model, scaler, meta


def _decision_score_to_anomaly_score(raw_score: float) -> float:
    """Linearly clip+invert decision_function output into a 0-1 anomaly_score."""
    clipped = max(_SCORE_CLIP_LOW, min(_SCORE_CLIP_HIGH, raw_score))
    normalized_normal = (clipped - _SCORE_CLIP_LOW) / (_SCORE_CLIP_HIGH - _SCORE_CLIP_LOW)
    return round(1.0 - normalized_normal, 4)


def score_flows(
    raw_tshark_csv_text: str,
    model_path: str = DEFAULT_MODEL_PATH,
    scaler_path: str = DEFAULT_SCALER_PATH,
    columns_path: str = DEFAULT_COLUMNS_PATH,
) -> list[dict[str, Any]]:
    """
    Build flows from raw per-packet CSV, extract features, and score each
    flow individually against the trained Isolation Forest baseline.

    Returns a list of per-flow result dicts.
    """
    model, scaler, meta = _load_artifacts(model_path, scaler_path, columns_path)

    flows = build_flows(raw_tshark_csv_text)
    if not flows:
        return []

    flow_items = list(flows.items())
    feature_matrix = np.array(
        [extract_features_for_flow(flow) for _, flow in flow_items], dtype=float
    )

    X_scaled = scaler.transform(feature_matrix)
    raw_scores = model.decision_function(X_scaled)   # higher = more normal
    raw_predictions = model.predict(X_scaled)         # -1 = anomaly, 1 = normal

    results: list[dict[str, Any]] = []
    for (key, flow), features, raw_score, raw_pred in zip(
        flow_items, feature_matrix, raw_scores, raw_predictions
    ):
        anomaly_score = _decision_score_to_anomaly_score(float(raw_score))
        results.append({
            "flow_key": str(key),
            "src": f"{flow['fwd_src_ip']}:{flow['fwd_src_port']}",
            "dst": f"{flow['fwd_dst_ip']}:{flow['fwd_dst_port']}",
            "prediction": "MALICIOUS" if raw_pred == -1 else "SAFE",
            "anomaly_score": anomaly_score,
            "raw_decision_score": round(float(raw_score), 4),
            "feature_vector": dict(zip(FEATURE_NAMES, [round(float(v), 4) for v in features])),
        })

    return results


def predict_network_case(
    raw_tshark_csv_text: str,
    case_id: str,
    source_file: str,
    model_path: str = DEFAULT_MODEL_PATH,
    scaler_path: str = DEFAULT_SCALER_PATH,
    columns_path: str = DEFAULT_COLUMNS_PATH,
) -> dict[str, Any]:
    """
    Score every flow in a case and roll them up into a single case-level
    verdict (worst flow wins), matching the shape used by malware/predict.py.
    """
    try:
        flow_results = score_flows(raw_tshark_csv_text, model_path, scaler_path, columns_path)
    except (FileNotFoundError, ValueError) as e:
        return {
            "case_id": case_id,
            "source_file": source_file,
            "category": "network",
            "error": str(e),
        }

    if not flow_results:
        return {
            "case_id": case_id,
            "source_file": source_file,
            "category": "network",
            "error": "No valid TCP flows could be parsed from the provided tshark CSV.",
        }

    malicious_flows = [r for r in flow_results if r["prediction"] == "MALICIOUS"]
    worst_flow = max(flow_results, key=lambda r: r["anomaly_score"])

    case_prediction = "MALICIOUS" if malicious_flows else "SAFE"

    return {
        "case_id": case_id,
        "source_file": source_file,
        "category": "network",
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "ml_result": {
            "prediction": case_prediction,
            "anomaly_score": worst_flow["anomaly_score"],
            "total_flows_analyzed": len(flow_results),
            "malicious_flow_count": len(malicious_flows),
        },
        "worst_flow": worst_flow,
        "all_flows": flow_results,
    }


if __name__ == "__main__":
    # Smoke test using the same synthetic sample from tshark_flow_fields.py's
    # own __main__ block (C2-beacon-like pattern to 185.220.101.50:443).
    sample_csv = """1751234567.100000,10.0.0.5,185.220.101.50,54321,443,1420,0,0,1,1
1751234567.150000,185.220.101.50,10.0.0.5,443,54321,60,0,0,0,1
1751234567.200000,10.0.0.5,185.220.101.50,54321,443,1420,0,0,1,1
1751234567.250000,185.220.101.50,10.0.0.5,443,54321,60,0,0,0,1
"""
    if not os.path.exists(DEFAULT_MODEL_PATH):
        print(f"[!] Model not found at {DEFAULT_MODEL_PATH} — train it first with training/train_baseline.py")
    else:
        result = predict_network_case(sample_csv, case_id="smoke_test", source_file="sample.pcap")
        print(json.dumps(result, indent=2, ensure_ascii=False))
