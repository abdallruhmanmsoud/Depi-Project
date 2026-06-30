"""
train_disk_model.py
====================
Stage 5 — Isolation Forest Training with Hyperparameter Search.

Loads:    disk/dataset/disk_train.csv  (SAFE cases only)
Searches: contamination in [0.01, 0.02, 0.05, 0.10, 0.15, 0.20]
Selects:  best contamination by highest F1 with reasonable FPR
Trains:   Final IsolationForest with best contamination
Scales:   StandardScaler (fit on SAFE training data)

Saves:
    disk/models/disk_model.pkl
    disk/models/disk_scaler.pkl
    disk/models/feature_order.json
    disk/models/training_metadata.json

Also generates:
    disk/evaluation/contamination_comparison.csv

Usage:
    python disk/training/train_disk_model.py
"""

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix,
)

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DISK_DIR     = os.path.dirname(SCRIPT_DIR)

TRAIN_CSV    = os.path.join(DISK_DIR, "dataset",    "disk_train.csv")
TEST_CSV     = os.path.join(DISK_DIR, "dataset",    "disk_test.csv")
MODELS_DIR   = os.path.join(DISK_DIR, "models")
EVAL_DIR     = os.path.join(DISK_DIR, "evaluation")

MODEL_PATH   = os.path.join(MODELS_DIR, "disk_model.pkl")
SCALER_PATH  = os.path.join(MODELS_DIR, "disk_scaler.pkl")
FEAT_ORDER   = os.path.join(MODELS_DIR, "feature_order.json")
METADATA     = os.path.join(MODELS_DIR, "training_metadata.json")
CONTAMINATION_CSV = os.path.join(EVAL_DIR, "contamination_comparison.csv")

CATEGORICAL = {"filesystem_type"}

# Contamination values to search
CONTAMINATION_VALUES = [0.01, 0.02, 0.05, 0.10, 0.15, 0.20]

IF_BASE_PARAMS = dict(
    n_estimators=200,
    max_samples="auto",
    max_features=1.0,
    bootstrap=False,
    random_state=42,
    n_jobs=-1,
)


def load_data(train_csv: str, test_csv: str):
    print(f"[INFO] Loading training data: {train_csv}")
    train_df = pd.read_csv(train_csv, low_memory=False)
    print(f"       {len(train_df):,} rows loaded")

    print(f"[INFO] Loading test data    : {test_csv}")
    test_df  = pd.read_csv(test_csv, low_memory=False)
    print(f"       {len(test_df):,} rows loaded")

    return train_df, test_df


def select_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
    exclude = {"case_id", "source_tool", "label"} | CATEGORICAL
    cols = [c for c in df.columns
            if c not in exclude and pd.api.types.is_numeric_dtype(df[c])]
    return df[cols].fillna(0), cols


def evaluate_contamination(
    c: float,
    X_train_scaled: np.ndarray,
    X_test_scaled:  np.ndarray,
    y_test:         np.ndarray,
    scaler:         StandardScaler,
    feature_names:  List[str],
) -> Dict:
    model = IsolationForest(contamination=c, **IF_BASE_PARAMS)
    model.fit(X_train_scaled)

    preds  = model.predict(X_test_scaled)          # +1=safe, -1=malicious
    scores = model.score_samples(X_test_scaled)    # lower = more anomalous

    y_pred = (preds == -1).astype(int)
    anomaly_scores = -scores

    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec  = float(recall_score(y_test, y_pred, zero_division=0))
    f1   = float(f1_score(y_test, y_pred, zero_division=0))

    try:
        roc = float(roc_auc_score(y_test, anomaly_scores))
    except Exception:
        roc = 0.0

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    tnr = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0

    return {
        "contamination":  c,
        "precision":      round(prec, 6),
        "recall":         round(rec,  6),
        "f1_score":       round(f1,   6),
        "roc_auc":        round(roc,  6),
        "fpr":            round(fpr,  6),
        "tnr":            round(tnr,  6),
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "false_positives":int(fp),
        "false_negatives":int(fn),
    }


def select_best(results: List[Dict]) -> Dict:
    """
    Select contamination with highest F1 that keeps FPR <= 0.10.
    If no result satisfies FPR constraint, pick highest F1 overall.
    """
    constrained = [r for r in results if r["fpr"] <= 0.10]
    pool = constrained if constrained else results
    return max(pool, key=lambda r: r["f1_score"])


def main():
    ap = argparse.ArgumentParser(description="Disk AI — Model Training")
    ap.add_argument("--train-csv", default=TRAIN_CSV)
    ap.add_argument("--test-csv",  default=TEST_CSV)
    args = ap.parse_args()

    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(EVAL_DIR,   exist_ok=True)

    print("=" * 60)
    print("  Disk AI — Isolation Forest Training")
    print("=" * 60)
    print()

    t0 = time.time()

    # ── Load data ─────────────────────────────────────────────────────────────
    train_df, test_df = load_data(args.train_csv, args.test_csv)
    print()

    # ── Feature selection ─────────────────────────────────────────────────────
    X_train_df, feature_names = select_features(
        train_df[train_df["label"] == "SAFE"] if "label" in train_df.columns else train_df)
    X_test_df, _ = select_features(test_df)

    print(f"[INFO] Numeric features      : {len(feature_names)}")
    print(f"[INFO] SAFE training samples : {len(X_train_df):,}")
    print(f"[INFO] Test samples          : {len(X_test_df):,}")

    y_test = (test_df["label"] == "MALICIOUS").astype(int).to_numpy()
    print(f"[INFO] Test MALICIOUS        : {int(y_test.sum()):,}")
    print()

    # ── Scale ─────────────────────────────────────────────────────────────────
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_df.to_numpy(dtype=np.float64))
    X_test_scaled  = scaler.transform(X_test_df.to_numpy(dtype=np.float64))
    print("[INFO] StandardScaler fitted on SAFE training data.")
    print()

    # ── Hyperparameter search ─────────────────────────────────────────────────
    print("=" * 60)
    print("  Contamination Hyperparameter Search")
    print("=" * 60)
    print(f"  {'Contam':>8}  {'Prec':>8}  {'Recall':>8}  {'F1':>8}  "
          f"{'FPR':>8}  {'TNR':>8}  {'ROC-AUC':>8}")
    print("  " + "-" * 56)

    search_results = []
    for c in CONTAMINATION_VALUES:
        res = evaluate_contamination(
            c, X_train_scaled, X_test_scaled,
            y_test, scaler, feature_names)
        search_results.append(res)
        print(f"  {c:>8.2f}  {res['precision']:>8.4f}  {res['recall']:>8.4f}  "
              f"{res['f1_score']:>8.4f}  {res['fpr']:>8.4f}  "
              f"{res['tnr']:>8.4f}  {res['roc_auc']:>8.4f}")

    # ── Save contamination comparison CSV ─────────────────────────────────────
    with open(CONTAMINATION_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(search_results[0].keys()))
        w.writeheader()
        w.writerows(search_results)
    print(f"\n[INFO] Contamination comparison saved: {CONTAMINATION_CSV}")

    # ── Select best ───────────────────────────────────────────────────────────
    best = select_best(search_results)
    print()
    print(f"[INFO] Selected contamination : {best['contamination']}")
    print(f"       F1-score = {best['f1_score']:.4f} | FPR = {best['fpr']:.4f} | "
          f"ROC-AUC = {best['roc_auc']:.4f}")
    print()

    # ── Final training ────────────────────────────────────────────────────────
    print("[INFO] Training final model ...")
    final_model = IsolationForest(
        contamination=best["contamination"], **IF_BASE_PARAMS)
    final_model.fit(X_train_scaled)
    train_time = time.time() - t0

    # Training score summary
    train_scores = final_model.score_samples(X_train_scaled)
    train_preds  = final_model.predict(X_train_scaled)
    n_in  = int((train_preds ==  1).sum())
    n_out = int((train_preds == -1).sum())
    print(f"[INFO] Training inliers  : {n_in:,}  ({100*n_in/len(train_preds):.1f}%)")
    print(f"[INFO] Training outliers : {n_out:,}  ({100*n_out/len(train_preds):.1f}%)")
    print(f"[INFO] Score range       : [{train_scores.min():.4f}, {train_scores.max():.4f}]")
    print()

    # ── Save artifacts ────────────────────────────────────────────────────────
    joblib.dump(final_model, MODEL_PATH)
    joblib.dump(scaler,      SCALER_PATH)

    with open(FEAT_ORDER, "w") as f:
        json.dump({"feature_order": feature_names}, f, indent=2)

    metadata = {
        "trained_at":               datetime.now(timezone.utc).isoformat(),
        "training_csv":             args.train_csv,
        "test_csv":                 args.test_csv,
        "training_samples":         len(X_train_df),
        "n_features":               len(feature_names),
        "feature_names":            feature_names,
        "categorical_excluded":     sorted(CATEGORICAL),
        "contamination_search":     CONTAMINATION_VALUES,
        "selected_contamination":   best["contamination"],
        "selection_criteria":       "highest F1 with FPR <= 0.10",
        "best_search_result":       best,
        "all_search_results":       search_results,
        "model_params":             {**IF_BASE_PARAMS,
                                     "contamination": best["contamination"]},
        "scaler":                   "StandardScaler",
        "train_time_seconds":       round(train_time, 3),
        "training_inliers":         n_in,
        "training_outliers":        n_out,
        "score_min":                float(train_scores.min()),
        "score_max":                float(train_scores.max()),
        "score_mean":               float(train_scores.mean()),
    }

    with open(METADATA, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[INFO] Saved: {MODEL_PATH}")
    print(f"[INFO] Saved: {SCALER_PATH}")
    print(f"[INFO] Saved: {FEAT_ORDER}")
    print(f"[INFO] Saved: {METADATA}")

    print()
    print("=" * 60)
    print("  Training Complete")
    print("=" * 60)
    print(f"  Training samples     : {len(X_train_df):,}")
    print(f"  Features             : {len(feature_names)}")
    print(f"  Best contamination   : {best['contamination']}")
    print(f"  Best F1              : {best['f1_score']:.4f}")
    print(f"  Train time           : {train_time:.2f}s")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()
