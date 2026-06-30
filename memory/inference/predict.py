"""
Isolation Forest Inference — predict.py
========================================
Loads a trained Isolation Forest model and scores a new memory case.

Usage:
    python predict.py <path_to_memory_feature_vector.json>

Input:
    JSON file containing exactly 164 numerical features
    (produced by memory_feature_builder.py or pipeline_test_runner.py)

Output (stdout + return value):
    {
        "anomaly_score": float,       # Lower = more anomalous
        "prediction": "normal" | "anomalous",
        "case": "<input filename>"
    }

Loads from:
    memory/models/isolation_forest.pkl
    memory/models/scaler.pkl
    memory/models/feature_columns.json
"""

import json
import os
import sys

import joblib
import numpy as np

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
MEMORY_DIR  = os.path.dirname(SCRIPT_DIR)
MODELS_DIR  = os.path.join(MEMORY_DIR, "models")

MODEL_PATH    = os.path.join(MODELS_DIR, "isolation_forest.pkl")
SCALER_PATH   = os.path.join(MODELS_DIR, "scaler.pkl")
FEATURES_PATH = os.path.join(MODELS_DIR, "feature_columns.json")


def load_artifacts():
    """Load the trained model, scaler and feature list."""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}\nRun training/train_isolation_forest.py first.")
    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(f"Scaler not found: {SCALER_PATH}")
    if not os.path.exists(FEATURES_PATH):
        raise FileNotFoundError(f"Feature columns not found: {FEATURES_PATH}")

    model   = joblib.load(MODEL_PATH)
    scaler  = joblib.load(SCALER_PATH)
    with open(FEATURES_PATH, "r", encoding="utf-8") as f:
        feature_cols = json.load(f)

    return model, scaler, feature_cols


def predict(feature_vector_path: str) -> dict:
    """
    Score a single memory_feature_vector.json file.

    Args:
        feature_vector_path: Path to a memory_feature_vector.json file

    Returns:
        dict with anomaly_score, prediction, and metadata
    """
    model, scaler, feature_cols = load_artifacts()

    # Load feature vector
    with open(feature_vector_path, "r", encoding="utf-8") as f:
        features = json.load(f)

    # Build feature array in the correct column order
    missing = [c for c in feature_cols if c not in features]
    if missing:
        print(f"[WARN] {len(missing)} missing features — filling with 0: {missing[:5]}...")

    X = np.array([[features.get(c, 0) for c in feature_cols]], dtype=float)

    # Scale and predict
    X_scaled     = scaler.transform(X)
    raw_score    = float(model.score_samples(X_scaled)[0])
    prediction   = model.predict(X_scaled)[0]
    label        = "anomalous" if prediction == -1 else "normal"

    case_name = os.path.basename(os.path.dirname(feature_vector_path))
    if not case_name:
        case_name = os.path.basename(feature_vector_path)

    result = {
        "case":          case_name,
        "input_file":    feature_vector_path,
        "anomaly_score": round(raw_score, 6),
        "prediction":    label,
        "features_used": len(feature_cols),
        "missing_features": len(missing),
        "threshold_note": "score < 0 typically indicates anomaly; exact threshold depends on contamination setting",
    }

    return result


def main():
    if len(sys.argv) < 2:
        print("Usage: python predict.py <path_to_memory_feature_vector.json>")
        print()
        print("Example:")
        print("  python predict.py ../tests/Win11Dump_runner_20260622_080128/memory_feature_vector.json")
        sys.exit(1)

    input_path = sys.argv[1]

    if not os.path.exists(input_path):
        print(f"[ERROR] File not found: {input_path}")
        sys.exit(1)

    try:
        result = predict(input_path)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

    output = json.dumps(result, indent=4)
    print(output)
    return result


if __name__ == "__main__":
    main()
