"""
train_baseline.py
───────────────────
Trains an Isolation Forest model on the CICIDS2017 Monday-WorkingHours.csv
dataset (the all-BENIGN baseline file), using the SAME 15-feature subset
that feature_extractor.py computes at inference time.

Split: 85% training / 15% validation
  - Scaler + model trained on the 85% only.
  - The 15% validation set is used ONLY to sanity-check the anomaly rate
    on held-out benign data (expect ~5% flagged, matching contamination param).

Output artifacts (saved into ai_engine/network/models/):
    network_isolation_forest.pkl   — trained sklearn model
    network_scaler.pkl             — StandardScaler fit on 85% train set only
    feature_columns.json           — feature order + training metadata

Usage:
    cd ai_engine\\network
    python training\\train_baseline.py ^
        --csv "path\\to\\Monday-WorkingHours.pcap_ISCX.csv" ^
        --out "models"
"""

from __future__ import annotations
import argparse
import json
import os
import sys
import time

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from feature_extraction.feature_extractor import FEATURE_NAMES

# ── Hyperparameters ──────────────────────────────────────────────────────────
CONTAMINATION = 0.05   # mirrors architecture config.yaml example
N_ESTIMATORS  = 200
RANDOM_STATE  = 42
TRAIN_RATIO   = 0.85   # 85% train / 15% validation


def load_and_clean(csv_path: str) -> pd.DataFrame:
    print(f"[+] Loading {csv_path} ...")
    t0 = time.time()
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"    Read {len(df):,} rows in {time.time()-t0:.1f}s")

    df.columns = [c.strip() for c in df.columns]

    missing = [c for c in FEATURE_NAMES if c not in df.columns]
    if missing:
        raise ValueError(f"Missing expected CICIDS columns: {missing}")

    df = df[FEATURE_NAMES].copy()

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    df.dropna(inplace=True)
    dropped = before - len(df)
    if dropped:
        print(f"[+] Dropped {dropped:,} rows with inf/NaN ({dropped/before*100:.2f}%)")

    print(f"[+] Clean dataset: {len(df):,} rows x {len(FEATURE_NAMES)} features")
    return df


def train(csv_path: str, output_dir: str) -> None:
    df = load_and_clean(csv_path)
    X = df.values.astype(float)

    # ── 85 / 15 split ────────────────────────────────────────────────────────
    X_train, X_val = train_test_split(
        X, test_size=1 - TRAIN_RATIO, random_state=RANDOM_STATE, shuffle=True
    )
    print(f"\n[+] Split -> Train: {len(X_train):,} rows  |  Val: {len(X_val):,} rows")

    # ── Scale (fit on train only, transform both) ─────────────────────────────
    print("[+] Fitting StandardScaler on training set ...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled   = scaler.transform(X_val)

    # ── Train Isolation Forest ────────────────────────────────────────────────
    print(f"[+] Training Isolation Forest "
          f"(n_estimators={N_ESTIMATORS}, contamination={CONTAMINATION}) ...")
    t0 = time.time()
    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train_scaled)
    print(f"    Training done in {time.time()-t0:.1f}s")

    # ── Save artifacts ────────────────────────────────────────────────────────
    os.makedirs(output_dir, exist_ok=True)
    model_path   = os.path.join(output_dir, "network_isolation_forest.pkl")
    scaler_path  = os.path.join(output_dir, "network_scaler.pkl")
    columns_path = os.path.join(output_dir, "feature_columns.json")

    joblib.dump(model,  model_path)
    joblib.dump(scaler, scaler_path)
    with open(columns_path, "w", encoding="utf-8") as f:
        json.dump({
            "feature_names": FEATURE_NAMES,
            "contamination": CONTAMINATION,
            "n_estimators": N_ESTIMATORS,
            "train_ratio": TRAIN_RATIO,
            "trained_on": os.path.basename(csv_path),
            "training_rows": len(X_train),
            "validation_rows": len(X_val),
        }, f, indent=2)

    print(f"\n[+] Saved model:   {model_path}")
    print(f"[+] Saved scaler:  {scaler_path}")
    print(f"[+] Saved columns: {columns_path}")

    # ── Validation results ────────────────────────────────────────────────────
    train_preds = model.predict(X_train_scaled)
    val_preds   = model.predict(X_val_scaled)
    val_scores  = model.score_samples(X_val_scaled)

    n_train_anom = int((train_preds == -1).sum())
    n_val_anom   = int((val_preds   == -1).sum())

    print(f"\n{'='*55}")
    print(f"  TRAINING SET   : {n_train_anom:>6,} / {len(X_train):,} anomalous "
          f"({n_train_anom/len(X_train)*100:.2f}%)  <- expected ~{CONTAMINATION*100:.0f}%")
    print(f"  VALIDATION SET : {n_val_anom:>6,} / {len(X_val):,} anomalous "
          f"({n_val_anom/len(X_val)*100:.2f}%)  <- should be ~{CONTAMINATION*100:.0f}%")
    print(f"  Val score mean : {val_scores.mean():.4f}")
    print(f"  Val score std  : {val_scores.std():.4f}")
    print(f"  Val score min  : {val_scores.min():.4f}  (most anomalous flow)")
    print(f"  Val score max  : {val_scores.max():.4f}  (most normal flow)")
    print(f"{'='*55}")
    print("\n[OK] Training complete.\n")


def main():
    parser = argparse.ArgumentParser(
        description="Train Network Isolation Forest baseline (85/15 split)"
    )
    parser.add_argument("--csv", required=True,
                        help="Path to Monday-WorkingHours.pcap_ISCX.csv")
    parser.add_argument("--out", required=True,
                        help="Output dir for model artifacts (e.g. models)")
    args = parser.parse_args()
    train(args.csv, args.out)


if __name__ == "__main__":
    main()
