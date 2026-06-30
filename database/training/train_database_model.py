"""
train_database_model.py
========================
Stage 7 — Isolation Forest Training for the Database AI Pipeline.

Loads:    dataset/database_train.csv  (SAFE cases only)
Trains:   sklearn IsolationForest on 53 numeric features
Scales:   StandardScaler (fit on training data)
Saves:
    models/database_model.pkl
    models/database_scaler.pkl
    models/feature_order.json
    models/training_metadata.json

Usage:
    python training/train_database_model.py
    python training/train_database_model.py --train-csv dataset/database_train.csv
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Any

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DATABASE_DIR = os.path.dirname(SCRIPT_DIR)

TRAIN_CSV        = os.path.join(DATABASE_DIR, "dataset", "database_train.csv")
MODELS_DIR       = os.path.join(DATABASE_DIR, "models")

MODEL_PATH       = os.path.join(MODELS_DIR, "database_model.pkl")
SCALER_PATH      = os.path.join(MODELS_DIR, "database_scaler.pkl")
FEATURE_ORDER    = os.path.join(MODELS_DIR, "feature_order.json")
METADATA_PATH    = os.path.join(MODELS_DIR, "training_metadata.json")

# ─── Categorical features (excluded from training) ───────────────────────────
CATEGORICAL_FEATURES = {"most_active_database", "most_active_table", "most_active_user"}

# ─── Isolation Forest hyperparameters ────────────────────────────────────────
# Tuned for a SAFE-only training set.
IF_PARAMS = {
    "n_estimators":   200,     # more trees = better coverage
    "max_samples":    "auto",
    "contamination":  0.02,    # expect ~2% noise in SAFE training data
    "max_features":   1.0,
    "bootstrap":      False,
    "random_state":   42,
    "n_jobs":         -1,
}


def load_training_data(csv_path: str) -> pd.DataFrame:
    """Load training CSV and return only SAFE rows."""
    print(f"[INFO] Loading training data: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"[INFO] Total rows loaded   : {len(df)}")

    if "label" in df.columns:
        df = df[df["label"] == "SAFE"].copy()
        print(f"[INFO] SAFE rows retained  : {len(df)}")

    return df


def select_numeric_features(df: pd.DataFrame) -> tuple:
    """
    Select all numeric feature columns, excluding metadata and categoricals.
    Returns (feature_df, feature_names).
    """
    exclude = {"case_id", "source_tool", "label"} | CATEGORICAL_FEATURES
    feature_cols = [c for c in df.columns if c not in exclude]

    # Keep only numeric
    numeric_cols = []
    for col in feature_cols:
        if pd.api.types.is_numeric_dtype(df[col]):
            numeric_cols.append(col)

    print(f"[INFO] Numeric features selected: {len(numeric_cols)}")
    return df[numeric_cols].fillna(0), numeric_cols


def train_model(X: np.ndarray) -> IsolationForest:
    print(f"[INFO] Training Isolation Forest ...")
    print(f"        n_estimators  = {IF_PARAMS['n_estimators']}")
    print(f"        contamination = {IF_PARAMS['contamination']}")
    print(f"        Training samples = {X.shape[0]}")
    print(f"        Features         = {X.shape[1]}")
    model = IsolationForest(**IF_PARAMS)
    model.fit(X)
    return model


def save_artifacts(model, scaler, feature_names: List[str], metadata: Dict) -> None:
    os.makedirs(MODELS_DIR, exist_ok=True)

    joblib.dump(model,  MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    with open(FEATURE_ORDER, "w") as f:
        json.dump({"feature_order": feature_names}, f, indent=2)

    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[INFO] Saved: {MODEL_PATH}")
    print(f"[INFO] Saved: {SCALER_PATH}")
    print(f"[INFO] Saved: {FEATURE_ORDER}")
    print(f"[INFO] Saved: {METADATA_PATH}")


def main():
    ap = argparse.ArgumentParser(description="Database AI — Isolation Forest Training")
    ap.add_argument("--train-csv", default=TRAIN_CSV)
    args = ap.parse_args()

    print("=" * 52)
    print("  Database AI — Isolation Forest Training")
    print("=" * 52)
    print()

    t0 = time.time()

    # ── Load data ─────────────────────────────────────────────────────────────
    df = load_training_data(args.train_csv)

    # ── Feature selection ─────────────────────────────────────────────────────
    X_df, feature_names = select_numeric_features(df)
    X_raw = X_df.to_numpy(dtype=np.float64)

    # ── Scale ─────────────────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)
    print(f"[INFO] Features scaled with StandardScaler")

    # ── Train ─────────────────────────────────────────────────────────────────
    model = train_model(X_scaled)
    train_time = time.time() - t0

    # ── Training scores summary ───────────────────────────────────────────────
    scores  = model.score_samples(X_scaled)        # raw anomaly scores
    preds   = model.predict(X_scaled)              # +1 = normal, -1 = anomaly
    n_inliers  = int((preds ==  1).sum())
    n_outliers = int((preds == -1).sum())

    print(f"[INFO] Training inliers  : {n_inliers}  ({100*n_inliers/len(preds):.1f}%)")
    print(f"[INFO] Training outliers : {n_outliers}  ({100*n_outliers/len(preds):.1f}%)")
    print(f"[INFO] Score range       : [{scores.min():.4f}, {scores.max():.4f}]")
    print(f"[INFO] Score mean        : {scores.mean():.4f}")

    # ── Save ─────────────────────────────────────────────────────────────────
    metadata = {
        "trained_at":           datetime.now(timezone.utc).isoformat(),
        "training_csv":         args.train_csv,
        "training_samples":     len(df),
        "n_features":           len(feature_names),
        "feature_names":        feature_names,
        "categorical_excluded": sorted(CATEGORICAL_FEATURES),
        "model_params":         IF_PARAMS,
        "scaler":               "StandardScaler",
        "train_time_seconds":   round(train_time, 3),
        "training_inliers":     n_inliers,
        "training_outliers":    n_outliers,
        "score_min":            float(scores.min()),
        "score_max":            float(scores.max()),
        "score_mean":           float(scores.mean()),
    }

    save_artifacts(model, scaler, feature_names, metadata)

    print()
    print("=" * 52)
    print("  Training Complete")
    print("=" * 52)
    print(f"  Training samples : {len(df)}")
    print(f"  Features trained : {len(feature_names)}")
    print(f"  Train time       : {train_time:.2f}s")
    print(f"  Model saved      : {MODEL_PATH}")
    print("=" * 52)
    print()


if __name__ == "__main__":
    main()
