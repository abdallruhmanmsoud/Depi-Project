"""
generate_malicious_only.py — scratch helper
Generates the 400 MALICIOUS cases and writes disk_test.csv.
Reuses the existing disk_train.csv (1200 SAFE).
Run from project root: python disk/dataset/generate_malicious_only.py
"""
import os, sys, random, time
import numpy as np
import pandas as pd

sys.path.insert(0, "disk/features")
sys.path.insert(0, "disk/dataset")

from disk_feature_builder   import DiskFeatureBuilder
from disk_dataset_builder   import (
    generate_malicious_records, ATTACK_TYPES,
    _get_feature_names, _vector_to_row, write_csv,
    TRAIN_CSV, TEST_CSV, FEATURE_NAMES,
)

random.seed(42)
np.random.seed(42)

FEATURE_NAMES[:] = _get_feature_names()

builder = DiskFeatureBuilder()

N_SAFE      = 1200
N_MALICIOUS = 400
SEED        = 42

print("[INFO] Loading existing SAFE CSV ...")
safe_df   = pd.read_csv(TRAIN_CSV, low_memory=False)
safe_rows = safe_df.to_dict("records")
print(f"       {len(safe_rows)} SAFE rows")

print("[INFO] Generating 400 MALICIOUS cases ...")
mal_rows = []
t0 = time.time()
for i in range(N_MALICIOUS):
    case_id     = N_SAFE + 1 + i
    attack_type = ATTACK_TYPES[i % len(ATTACK_TYPES)]
    records     = generate_malicious_records(attack_type, seed=SEED + case_id)
    vector      = builder._build(records)
    row         = _vector_to_row(case_id, "MALICIOUS", vector)
    mal_rows.append(row)
    if (i + 1) % 50 == 0:
        dr = vector.get("deletion_ratio", 0)
        rs = vector.get("overall_disk_risk_score", 0)
        print(f"  [{i+1:>4}/400] {attack_type:<30}  del_ratio={dr:.3f}  risk={rs:.0f}")

print(f"[INFO] 400 MALICIOUS cases in {time.time()-t0:.1f}s")

all_test = safe_rows + mal_rows
random.shuffle(all_test)
write_csv(all_test, TEST_CSV)
print(f"[INFO] Test CSV: {TEST_CSV}  ({len(all_test)} rows)")
print("Done.")
