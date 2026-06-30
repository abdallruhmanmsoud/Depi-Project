"""
validate_features.py
====================
Validates disk_feature_vector.json.

Checks:
    - All numeric features are finite (no NaN, no Inf)
    - No null numeric values
    - Minimum expected feature count
    - Key features present and within plausible ranges

Usage:
    python disk/features/validate_features.py
    python disk/features/validate_features.py disk/features/disk_feature_vector.json
"""

import json
import math
import os
import sys
from typing import Any, Dict

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DISK_DIR     = os.path.dirname(SCRIPT_DIR)
DEFAULT_PATH = os.path.join(DISK_DIR, "features", "disk_feature_vector.json")

MIN_FEATURES = 90   # minimum acceptable feature count

# Key features that must exist and be non-negative numeric
REQUIRED_NUMERIC = [
    "total_files", "total_directories", "total_entries",
    "deleted_files", "deleted_directories", "hidden_files", "orphan_files",
    "allocated_files", "avg_filename_length", "max_directory_depth",
    "avg_directory_depth", "avg_files_per_directory",
    "deletion_ratio", "allocation_ratio",
    "exec_file_count", "doc_file_count", "archive_file_count",
    "media_file_count", "script_file_count", "temp_file_count",
    "unique_extensions",
    "earliest_timestamp", "latest_timestamp", "timeline_duration",
    "activity_density", "creation_rate", "modification_rate",
    "timeline_event_count",
    "peak_activity_hour", "peak_activity_day",
    "weekend_activity", "night_activity",
    "creation_bursts", "modification_bursts", "deletion_bursts",
    "timestamp_gap_std", "timestamp_gap_mean",
    "allocated_inode_ratio", "deleted_inode_ratio", "orphan_inode_ratio",
    "metadata_density", "deleted_with_timestamps", "files_with_no_timestamp",
    "executables_in_temp", "executables_in_downloads", "executables_on_desktop",
    "deleted_executables", "hidden_executables", "double_extension_count",
    "suspicious_dir_files", "deletion_time_span",
    "exec_created_then_deleted", "high_modification_count",
    "persistence_indicators", "scripts_in_suspicious_dirs",
    "lnk_file_count", "recently_created_and_modified",
    "filesystem_health_score", "deletion_score",
    "execution_risk_score", "persistence_score",
    "timeline_risk_score", "artifact_density_score",
    "user_activity_score", "overall_disk_risk_score",
]

# Ranges: (min_val, max_val) — None means no bound
RANGE_CHECKS: Dict[str, tuple] = {
    "deletion_ratio":          (0.0, 1.0),
    "allocation_ratio":        (0.0, 1.0),
    "allocated_inode_ratio":   (0.0, 1.0),
    "deleted_inode_ratio":     (0.0, 1.0),
    "orphan_inode_ratio":      (0.0, 1.0),
    "night_activity_ratio":    (0.0, 1.0),
    "weekend_activity_ratio":  (0.0, 1.0),
    "filesystem_health_score": (0.0, 100.0),
    "peak_activity_hour":      (-1, 23),
    "peak_activity_day":       (-1, 6),
    "total_files":             (0, None),
    "total_directories":       (0, None),
    "exec_file_count":         (0, None),
}


def validate(path: str) -> bool:
    print(f"[INFO] Validating: {path}")
    print()

    with open(path, "r", encoding="utf-8") as f:
        vector: Dict[str, Any] = json.load(f)

    errors   = []
    warnings = []

    # Feature count
    n_total    = len(vector)
    numeric    = {k: v for k, v in vector.items() if isinstance(v, (int, float))}
    cat        = {k: v for k, v in vector.items() if not isinstance(v, (int, float))}

    print(f"  Total features       : {n_total}")
    print(f"  Numeric features     : {len(numeric)}")
    print(f"  Categorical features : {len(cat)}")
    print()

    if n_total < MIN_FEATURES:
        errors.append(f"Feature count {n_total} < minimum {MIN_FEATURES}")

    # NaN / Inf checks
    nan_count = 0
    inf_count = 0
    null_count = 0
    for k, v in vector.items():
        if isinstance(v, float):
            if math.isnan(v):
                errors.append(f"NaN in feature: {k}")
                nan_count += 1
            elif math.isinf(v):
                errors.append(f"Inf in feature: {k}")
                inf_count += 1
        if v is None and k in REQUIRED_NUMERIC:
            errors.append(f"Null in required numeric feature: {k}")
            null_count += 1

    print(f"  NaN values           : {nan_count}")
    print(f"  Inf values           : {inf_count}")
    print(f"  Null numeric         : {null_count}")
    print()

    # Required field presence
    missing = [f for f in REQUIRED_NUMERIC if f not in vector]
    if missing:
        for m in missing:
            errors.append(f"Missing required feature: {m}")

    # Range checks
    for feat, (lo, hi) in RANGE_CHECKS.items():
        val = vector.get(feat)
        if val is None:
            continue
        if lo is not None and val < lo:
            errors.append(f"{feat} = {val} < min {lo}")
        if hi is not None and val > hi:
            warnings.append(f"{feat} = {val} > expected max {hi}")

    # Print key values
    print("  Key Feature Values:")
    for k in [
        "total_files", "total_directories", "deleted_files",
        "exec_file_count", "deleted_executables", "hidden_executables",
        "executables_in_temp", "double_extension_count",
        "persistence_indicators", "creation_bursts", "deletion_bursts",
        "deletion_ratio", "execution_risk_score",
        "persistence_score", "overall_disk_risk_score",
    ]:
        val = vector.get(k)
        print(f"    {k:<40} : {val}")

    print()

    if warnings:
        print(f"  Warnings: {len(warnings)}")
        for w in warnings[:10]:
            print(f"    [WARN] {w}")
        print()

    n_errors = len(errors)
    print(f"  Validation Errors: {n_errors}")
    if n_errors > 0:
        for e in errors[:20]:
            print(f"    [ERR] {e}")
        print()
        print("  RESULT: VALIDATION FAILED")
    else:
        print()
        print("  RESULT: ALL CHECKS PASSED")

    return n_errors == 0


def main():
    path = sys.argv[1] if len(sys.argv) >= 2 else DEFAULT_PATH
    ok   = validate(path)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
