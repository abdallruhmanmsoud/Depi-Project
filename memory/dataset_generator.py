"""
Dataset Generator
=================
Collects all processed memory feature vectors from tests/ and builds
a production-ready CSV dataset for Isolation Forest training.

Reads all memory_feature_vector.json files from tests/*/
Generates:
  - memory/datasets/memory_dataset.csv
  - memory/datasets/dataset_validation_report.json

Features:
  - Auto-discovers all processed dumps
  - Prevents duplicate rows (by dump_name)
  - Validates feature schema consistency
  - Auto-labels case_type based on anomaly indicators
  - Adds metadata columns (case_id, dump_name, case_type, etc.)
"""

import csv
import json
import os
import sys
from datetime import datetime

# ── Paths ───────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TESTS_DIR = os.path.join(BASE_DIR, "tests")
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
DATASET_CSV = os.path.join(DATASETS_DIR, "memory_dataset.csv")
VALIDATION_REPORT = os.path.join(DATASETS_DIR, "dataset_validation_report.json")

EXPECTED_FEATURE_COUNT = 164


# ═══════════════════════════════════════════════════════════════════════════
#  AUTO-LABELING
# ═══════════════════════════════════════════════════════════════════════════

def classify_case(features: dict) -> str:
    """
    Auto-classify a memory case as 'safe' or 'suspicious'
    based on key anomaly indicators.

    A case is labeled suspicious if ANY of these thresholds are exceeded:
      - non-JIT RWX regions > 0    (code injection)
      - critical process malfind > 0 (lsass/csrss injection)
      - encoded commands > 0       (obfuscated execution)
      - download indicators > 0    (download cradle)
      - bypass indicators > 0      (security bypass)
      - singleton violations > 1   (process impersonation)
      - anomaly composite > 150    (aggregated risk)

    Otherwise the case is labeled 'safe'.
    This label is for evaluation only — Isolation Forest trains on safe only.
    """
    if features.get("mf_non_jit_rwx_count", 0) > 0:
        return "suspicious"
    if features.get("mf_critical_proc_findings", 0) > 0:
        return "suspicious"
    if features.get("cmd_encoded_command_count", 0) > 0:
        return "suspicious"
    if features.get("cmd_download_indicator_count", 0) > 0:
        return "suspicious"
    if features.get("cmd_bypass_indicator_count", 0) > 0:
        return "suspicious"
    if features.get("proc_singleton_violations", 0) > 1:
        return "suspicious"
    if features.get("cross_anomaly_composite_score", 0) > 150:
        return "suspicious"

    return "safe"


# ═══════════════════════════════════════════════════════════════════════════
#  DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════

def discover_dumps() -> list:
    """
    Scan tests/ directory for processed dumps.
    Returns list of (dump_name, feature_vector_path, validation_path).
    """
    dumps = []

    if not os.path.isdir(TESTS_DIR):
        print(f"[ERROR] Tests directory not found: {TESTS_DIR}")
        return dumps

    for entry in sorted(os.listdir(TESTS_DIR)):
        dump_dir = os.path.join(TESTS_DIR, entry)
        if not os.path.isdir(dump_dir):
            continue

        vector_path = os.path.join(dump_dir, "memory_feature_vector.json")
        val_path = os.path.join(dump_dir, "validation_report.json")

        if os.path.exists(vector_path):
            dumps.append((entry, vector_path, val_path))
        else:
            print(f"[WARN] No feature vector found for: {entry}")

    return dumps


# ═══════════════════════════════════════════════════════════════════════════
#  DATASET BUILDING
# ═══════════════════════════════════════════════════════════════════════════

def build_dataset():
    """Build memory_dataset.csv from all processed dumps."""

    print("=" * 70)
    print("  Dataset Generator")
    print("=" * 70)
    print()

    dumps = discover_dumps()
    print(f"[INFO] Discovered {len(dumps)} processed dumps")

    if not dumps:
        print("[ERROR] No processed dumps found. Run pipeline_test_runner.py first.")
        return

    # ── Load all feature vectors ──
    rows = []
    reference_keys = None
    schema_issues = []
    case_id = 0

    for dump_name, vector_path, val_path in dumps:
        case_id += 1
        print(f"\n[INFO] Loading: {dump_name}")

        try:
            with open(vector_path, "r", encoding="utf-8") as f:
                features = json.load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load {vector_path}: {e}")
            schema_issues.append(f"{dump_name}: failed to load feature vector")
            continue

        # ── Schema consistency check ──
        current_keys = sorted(features.keys())

        if reference_keys is None:
            reference_keys = current_keys
            print(f"  Reference schema set: {len(reference_keys)} features")
        else:
            if current_keys != reference_keys:
                missing = set(reference_keys) - set(current_keys)
                extra = set(current_keys) - set(reference_keys)
                if missing:
                    schema_issues.append(
                        f"{dump_name}: missing features: {list(missing)}"
                    )
                    print(f"  [WARN] Missing features: {missing}")
                if extra:
                    schema_issues.append(
                        f"{dump_name}: extra features: {list(extra)}"
                    )
                    print(f"  [WARN] Extra features: {extra}")
            else:
                print(f"  Schema matches reference ({len(current_keys)} features)")

        # ── Load record count from validation report ──
        record_count = 0
        if os.path.exists(val_path):
            try:
                with open(val_path, "r", encoding="utf-8") as f:
                    val_data = json.load(f)
                record_count = val_data.get("normalization", {}).get(
                    "total_normalized_records", 0
                )
            except Exception:
                pass

        # ── Classify ──
        case_type = classify_case(features)
        print(f"  Case type: {case_type}")
        print(f"  Features: {len(features)}")
        print(f"  Records: {record_count:,}")

        # ── Build row ──
        row = {
            "case_id": f"case_{case_id:04d}",
            "dump_name": dump_name,
            "case_type": case_type,
            "record_count": record_count,
            "feature_count": len(features),
        }
        # Add all features in reference key order
        for key in reference_keys:
            row[key] = features.get(key, 0)

        rows.append(row)

    # ── Deduplicate by dump_name ──
    seen = set()
    unique_rows = []
    duplicates = 0
    for row in rows:
        if row["dump_name"] not in seen:
            seen.add(row["dump_name"])
            unique_rows.append(row)
        else:
            duplicates += 1
            print(f"[WARN] Duplicate removed: {row['dump_name']}")

    # ── Write CSV ──
    os.makedirs(DATASETS_DIR, exist_ok=True)

    if not unique_rows:
        print("[ERROR] No valid rows to write.")
        return

    # Column order: metadata first, then features in sorted order
    metadata_cols = ["case_id", "dump_name", "case_type", "record_count", "feature_count"]
    feature_cols = list(reference_keys)
    all_cols = metadata_cols + feature_cols

    with open(DATASET_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_cols)
        writer.writeheader()
        writer.writerows(unique_rows)

    print(f"\n[INFO] Dataset saved: {DATASET_CSV}")
    print(f"[INFO] Rows: {len(unique_rows)}")
    print(f"[INFO] Columns: {len(all_cols)} (5 metadata + {len(feature_cols)} features)")

    # ── Missing value analysis ──
    missing_values = {}
    for row in unique_rows:
        for col in all_cols:
            val = row.get(col)
            if val is None or val == "":
                if col not in missing_values:
                    missing_values[col] = 0
                missing_values[col] += 1

    # ── Summary counts ──
    safe_count = sum(1 for r in unique_rows if r["case_type"] == "safe")
    suspicious_count = sum(1 for r in unique_rows if r["case_type"] == "suspicious")

    # ── Validation Report ──
    validation = {
        "timestamp": datetime.now().isoformat(),
        "dataset_path": DATASET_CSV,
        "total_dumps_discovered": len(dumps),
        "total_rows_written": len(unique_rows),
        "duplicates_removed": duplicates,
        "safe_cases": safe_count,
        "suspicious_cases": suspicious_count,
        "metadata_columns": len(metadata_cols),
        "feature_columns": len(feature_cols),
        "total_columns": len(all_cols),
        "expected_feature_count": EXPECTED_FEATURE_COUNT,
        "actual_feature_count": len(feature_cols),
        "feature_count_match": len(feature_cols) == EXPECTED_FEATURE_COUNT,
        "feature_consistency": "PASS" if not schema_issues else "FAIL",
        "schema_issues": schema_issues,
        "missing_values": missing_values if missing_values else "none",
        "duplicate_detection": "PASS" if duplicates == 0 else f"{duplicates} duplicates removed",
        "feature_names": feature_cols,
        "case_labels": {row["dump_name"]: row["case_type"] for row in unique_rows},
        "readiness": {
            "isolation_forest_ready": safe_count >= 2,
            "minimum_safe_cases": 10,
            "current_safe_cases": safe_count,
            "current_suspicious_cases": suspicious_count,
            "recommendation": (
                "Ready for initial Isolation Forest training"
                if safe_count >= 4
                else f"Need {max(0, 4 - safe_count)} more safe cases before training"
            ),
        },
    }

    with open(VALIDATION_REPORT, "w", encoding="utf-8") as f:
        json.dump(validation, f, indent=4, ensure_ascii=False)

    print(f"[INFO] Validation report saved: {VALIDATION_REPORT}")

    # ── Print final summary ──
    print()
    print("=" * 70)
    print("  DATASET SUMMARY")
    print("=" * 70)
    print(f"  Total dumps:          {len(unique_rows)}")
    print(f"  Safe cases:           {safe_count}")
    print(f"  Suspicious cases:     {suspicious_count}")
    print(f"  Feature columns:      {len(feature_cols)}")
    print(f"  Schema consistency:   {'PASS' if not schema_issues else 'FAIL'}")
    print(f"  Missing values:       {'none' if not missing_values else len(missing_values)}")
    print(f"  Duplicates removed:   {duplicates}")
    print()

    for row in unique_rows:
        icon = "+" if row["case_type"] == "safe" else "!"
        print(f"  [{icon}] {row['dump_name']}")
        print(f"      case_type={row['case_type']}  records={row['record_count']:,}  features={row['feature_count']}")

    print()
    print(f"  IF Training Ready:    {'YES' if safe_count >= 4 else 'NO'}")
    print(f"  Recommendation:       {validation['readiness']['recommendation']}")
    print()


if __name__ == "__main__":
    build_dataset()
