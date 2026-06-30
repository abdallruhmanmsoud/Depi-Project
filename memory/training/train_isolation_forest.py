"""
Isolation Forest Training Pipeline
===================================
Trains an Isolation Forest anomaly detection model on safe memory cases.

Input:
    memory/datasets/memory_dataset.csv

Training set:
    Rows where label == "safe"

Steps:
    1. Load dataset
    2. Load analyst labels (labels.csv)
    3. Filter to safe cases only
    4. StandardScaler fit on safe features
    5. IsolationForest fit on scaled safe features
    6. Validate on ALL cases (safe + suspicious)
    7. Save model artifacts

Outputs:
    memory/models/isolation_forest.pkl
    memory/models/scaler.pkl
    memory/models/feature_columns.json
    memory/training/training_report.json
"""

import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
MEMORY_DIR   = os.path.dirname(BASE_DIR)
DATASET_CSV  = os.path.join(MEMORY_DIR, "datasets", "memory_dataset.csv")
LABELS_CSV   = os.path.join(MEMORY_DIR, "datasets", "labels.csv")
MODELS_DIR   = os.path.join(MEMORY_DIR, "models")
TRAINING_DIR = BASE_DIR

MODEL_PATH   = os.path.join(MODELS_DIR, "isolation_forest.pkl")
SCALER_PATH  = os.path.join(MODELS_DIR, "scaler.pkl")
FEATURES_PATH = os.path.join(MODELS_DIR, "feature_columns.json")
REPORT_PATH  = os.path.join(TRAINING_DIR, "training_report.json")

# ── Hyperparameters ──────────────────────────────────────────────────────────
IF_CONTAMINATION = "auto"   # unsupervised: no assumed contamination
IF_N_ESTIMATORS  = 200
IF_MAX_SAMPLES   = "auto"
IF_RANDOM_STATE  = 42


def load_labels(path):
    """Load analyst labels from labels.csv. Returns dict {dump_name: label}."""
    labels = {}
    df = pd.read_csv(path, encoding="utf-8")
    for _, row in df.iterrows():
        labels[str(row["case_id"]).strip()] = str(row["label"]).strip()
    return labels


def load_dataset(path):
    """Load memory_dataset.csv into a DataFrame."""
    df = pd.read_csv(path, encoding="utf-8")
    print(f"[INFO] Loaded dataset: {len(df)} rows, {len(df.columns)} columns")
    return df


def get_feature_columns(df):
    """Extract pure numerical feature columns (exclude all metadata)."""
    NON_FEATURE = {"case_id", "dump_name", "label", "case_type",
                   "record_count", "feature_count"}
    feat_cols = [c for c in df.columns if c not in NON_FEATURE]
    return feat_cols


def train(df, feat_cols, labels):
    """Run the full training pipeline."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    # ── Apply analyst labels ─────────────────────────────────────────────────
    if "label" not in df.columns:
        df["label"] = df["dump_name"].map(labels).fillna("unlabeled")
    else:
        # Override existing label column with analyst ground truth
        df["label"] = df["dump_name"].map(labels).fillna(df["label"])

    print(f"\n[INFO] Label distribution:")
    print(df["label"].value_counts().to_string())

    # ── Training set: safe only ──────────────────────────────────────────────
    df_safe = df[df["label"] == "safe"].copy()
    print(f"\n[INFO] Training set: {len(df_safe)} safe cases")
    print(f"[INFO] Safe cases used:")
    for name in df_safe["dump_name"].tolist():
        print(f"         - {name}")

    if len(df_safe) == 0:
        print("[ERROR] No safe cases found. Cannot train.")
        sys.exit(1)

    X_safe = df_safe[feat_cols].values.astype(float)

    # ── StandardScaler ───────────────────────────────────────────────────────
    print(f"\n[INFO] Fitting StandardScaler on {X_safe.shape[0]} safe cases x {X_safe.shape[1]} features...")
    scaler = StandardScaler()
    X_safe_scaled = scaler.fit_transform(X_safe)

    # ── IsolationForest ──────────────────────────────────────────────────────
    print(f"[INFO] Training IsolationForest (n_estimators={IF_N_ESTIMATORS}, contamination={IF_CONTAMINATION}, random_state={IF_RANDOM_STATE})...")
    iso = IsolationForest(
        n_estimators=IF_N_ESTIMATORS,
        max_samples=IF_MAX_SAMPLES,
        contamination=IF_CONTAMINATION,
        random_state=IF_RANDOM_STATE,
        n_jobs=-1,
    )
    iso.fit(X_safe_scaled)
    print("[INFO] Training complete.")

    # ── Save artifacts ───────────────────────────────────────────────────────
    joblib.dump(iso,    MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    with open(FEATURES_PATH, "w", encoding="utf-8") as f:
        json.dump(feat_cols, f, indent=4)

    print(f"\n[INFO] Saved: {MODEL_PATH}")
    print(f"[INFO] Saved: {SCALER_PATH}")
    print(f"[INFO] Saved: {FEATURES_PATH}")

    return iso, scaler, df_safe


def validate(iso, scaler, df, feat_cols, labels):
    """Run inference on ALL cases and generate training report."""
    # Apply labels
    df["label"] = df["dump_name"].map(labels).fillna(df.get("label", "unlabeled"))

    X_all = df[feat_cols].values.astype(float)
    X_all_scaled = scaler.transform(X_all)

    # Anomaly scores: lower (more negative) = more anomalous
    raw_scores  = iso.score_samples(X_all_scaled)   # decision function values
    predictions = iso.predict(X_all_scaled)          # +1 = normal, -1 = anomalous

    # Build per-case results
    case_results = []
    for i, (_, row) in enumerate(df.iterrows()):
        case_results.append({
            "rank":          0,  # filled below
            "dump_name":     row["dump_name"],
            "label":         row["label"],
            "anomaly_score": round(float(raw_scores[i]), 6),
            "prediction":    "anomalous" if predictions[i] == -1 else "normal",
            "cross_anomaly_composite_score": float(row.get("cross_anomaly_composite_score", 0)),
        })

    # Rank by anomaly_score ascending (most anomalous first)
    case_results.sort(key=lambda x: x["anomaly_score"])
    for rank, c in enumerate(case_results, 1):
        c["rank"] = rank

    # Validation stats
    n_anomalous = sum(1 for c in case_results if c["prediction"] == "anomalous")
    n_normal    = sum(1 for c in case_results if c["prediction"] == "normal")

    # Check: DESKTOP-88S7USO should be most anomalous
    most_anomalous = case_results[0]["dump_name"]
    desktop_check  = "PASS" if "DESKTOP-88S7USO" in most_anomalous else "FAIL"

    report = {
        "timestamp":          datetime.now().isoformat(),
        "model":              MODEL_PATH,
        "scaler":             SCALER_PATH,
        "feature_columns":    FEATURES_PATH,
        "training_set": {
            "cases_used":        [c["dump_name"] for c in case_results if c["label"] == "safe"],
            "safe_case_count":   sum(1 for c in case_results if c["label"] == "safe"),
            "feature_count":     len(feat_cols),
            "n_estimators":      IF_N_ESTIMATORS,
            "contamination":     str(IF_CONTAMINATION),
            "random_state":      IF_RANDOM_STATE,
            "scaler":            "StandardScaler",
        },
        "validation": {
            "total_cases_scored": len(case_results),
            "predicted_anomalous": n_anomalous,
            "predicted_normal":    n_normal,
            "highest_anomaly_check": {
                "expected":  "DESKTOP-88S7USO",
                "actual":    most_anomalous,
                "status":    desktop_check,
            },
        },
        "case_scores": case_results,
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)
    print(f"[INFO] Training report saved: {REPORT_PATH}")

    # Print table
    print(f"\n{'='*70}")
    print("  Anomaly Score Table (most anomalous first)")
    print(f"{'='*70}")
    print(f"  {'Rank':<5} {'Case':<55} {'Score':>10} {'Pred':<12} {'Label'}")
    print(f"  {'-'*5} {'-'*55} {'-'*10} {'-'*12} {'-'*10}")
    for c in case_results:
        print(f"  #{c['rank']:<4} {c['dump_name']:<55} {c['anomaly_score']:>10.6f} {c['prediction']:<12} {c['label']}")

    print(f"\n  Highest anomaly: {most_anomalous}")
    print(f"  DESKTOP check:   {desktop_check}")

    return report


def main():
    print()
    print("="*70)
    print("  Isolation Forest Training Pipeline")
    print("="*70)

    labels  = load_labels(LABELS_CSV)
    df      = load_dataset(DATASET_CSV)
    feat_cols = get_feature_columns(df)

    print(f"\n[INFO] Feature columns: {len(feat_cols)}")

    iso, scaler, df_safe = train(df, feat_cols, labels)
    report = validate(iso, scaler, df, feat_cols, labels)

    print(f"\n{'='*70}")
    print("  Training Complete")
    print(f"{'='*70}")
    print(f"  Model:            {MODEL_PATH}")
    print(f"  Scaler:           {SCALER_PATH}")
    print(f"  Feature columns:  {FEATURES_PATH}")
    print(f"  Training report:  {REPORT_PATH}")
    print()


if __name__ == "__main__":
    main()
