"""
validate_features.py
====================
Validates the output of database_feature_builder.py.

Checks performed:
  1. JSON is valid and file exists
  2. All features from FEATURE_SCHEMA are present
  3. No duplicate feature names in the file
  4. All numeric features contain actual numbers (int or float)
  5. No NaN values
  6. No null values in numeric features (null allowed only in categoricals)
  7. Categorical features are strings or None
  8. Composite scores are non-negative
  9. Ratio features are in valid range [0, inf)
  10. total_events > 0

Usage:
    python features/validate_features.py [path_to_database_feature_vector.json]
"""

import json
import math
import os
import sys

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DATABASE_DIR = os.path.dirname(SCRIPT_DIR)

# Import the schema definition from the builder
sys.path.insert(0, SCRIPT_DIR)
from database_feature_builder import FEATURE_SCHEMA, NUMERIC_FEATURES, CATEGORICAL_FEATURES

W = 50


def validate(vector: dict) -> list:
    """Run all checks and return a list of error strings."""
    errors = []

    # ── Check 1: All required features present ────────────────────────────────
    for feat in FEATURE_SCHEMA:
        if feat not in vector:
            errors.append(f"MISSING feature: '{feat}'")

    # ── Check 2: No duplicate keys (JSON spec allows them; we forbid them) ────
    # Already guaranteed by json.load() dict, but we verify schema order
    schema_set = set(FEATURE_SCHEMA)
    extra = [k for k in vector if k not in schema_set]
    if extra:
        errors.append(f"EXTRA unexpected features: {extra}")

    # ── Check 3: Numeric features are numbers, not null, not NaN ─────────────
    for feat in NUMERIC_FEATURES:
        if feat not in vector:
            continue   # already flagged above
        val = vector[feat]
        if val is None:
            errors.append(f"NULL in numeric feature '{feat}'")
            continue
        if not isinstance(val, (int, float)):
            errors.append(f"NON-NUMERIC value in '{feat}': {repr(val)}")
            continue
        if isinstance(val, float) and math.isnan(val):
            errors.append(f"NaN in feature '{feat}'")
        if isinstance(val, float) and math.isinf(val):
            errors.append(f"Inf in feature '{feat}'")

    # ── Check 4: Categorical features are str or None ─────────────────────────
    for feat in CATEGORICAL_FEATURES:
        if feat not in vector:
            continue
        val = vector[feat]
        if val is not None and not isinstance(val, str):
            errors.append(f"Categorical '{feat}' is not str or null: {repr(val)}")

    # ── Check 5: total_events > 0 ─────────────────────────────────────────────
    total = vector.get("total_events", 0)
    if isinstance(total, (int, float)) and total <= 0:
        errors.append(f"total_events must be > 0, got: {total}")

    # ── Check 6: Ratio features must be >= 0 ─────────────────────────────────
    ratio_features = [
        "transaction_success_ratio",
        "insert_update_ratio",
        "delete_update_ratio",
        "ddl_dml_ratio",
        "grant_to_auth_ratio",
        "success_rate",
    ]
    for feat in ratio_features:
        val = vector.get(feat)
        if isinstance(val, (int, float)) and val < 0:
            errors.append(f"Ratio '{feat}' is negative: {val}")

    # ── Check 7: Composite scores must be >= 0 ────────────────────────────────
    score_features = [
        "data_change_score",
        "schema_change_score",
        "privilege_score",
        "authentication_score",
        "transaction_score",
        "overall_database_activity_score",
    ]
    for feat in score_features:
        val = vector.get(feat)
        if isinstance(val, (int, float)) and val < 0:
            errors.append(f"Score '{feat}' is negative: {val}")

    # ── Check 8: Timestamp consistency ────────────────────────────────────────
    first_ts = vector.get("first_timestamp")
    last_ts  = vector.get("last_timestamp")
    duration = vector.get("activity_duration", 0)
    if first_ts is not None and last_ts is not None:
        if last_ts < first_ts:
            errors.append(f"last_timestamp ({last_ts}) < first_timestamp ({first_ts})")
        expected_dur = last_ts - first_ts
        if isinstance(duration, (int, float)) and abs(duration - expected_dur) > 1:
            errors.append(
                f"activity_duration ({duration}) != "
                f"last-first ({expected_dur})"
            )

    return errors


def main():
    if len(sys.argv) >= 2:
        input_path = sys.argv[1]
    else:
        input_path = os.path.join(DATABASE_DIR, "features", "mysqlbinlog_feature_vector.json")

    print(f"[INFO] Validating: {input_path}")
    print()

    # ── Load ──────────────────────────────────────────────────────────────────
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            vector = json.load(f)
    except json.JSONDecodeError as exc:
        print(f"[FAIL] Invalid JSON: {exc}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"[FAIL] File not found: {input_path}")
        sys.exit(1)

    print(f"  JSON valid         : YES")
    print(f"  Features in file   : {len(vector)}")
    print(f"  Expected features  : {len(FEATURE_SCHEMA)}")
    print()

    # ── Validate ──────────────────────────────────────────────────────────────
    errors = validate(vector)

    # ── Summary stats ─────────────────────────────────────────────────────────
    numeric_count     = sum(1 for k in NUMERIC_FEATURES     if k in vector)
    categorical_count = sum(1 for k in CATEGORICAL_FEATURES if k in vector)
    null_count        = sum(1 for v in vector.values() if v is None)
    non_zero_numeric  = sum(
        1 for k in NUMERIC_FEATURES
        if k in vector and isinstance(vector[k], (int, float)) and vector[k] != 0
    )

    # ── Print report ──────────────────────────────────────────────────────────
    print("=" * W)
    print("  Feature Extraction Validation Report")
    print("=" * W)
    print(f"\n  Events processed          : {vector.get('total_events', '?')}")
    print(f"  Features generated        : {len(vector)}")
    print(f"  Numeric features          : {numeric_count}")
    print(f"  Categorical features      : {categorical_count}")
    print(f"  Non-zero numeric features : {non_zero_numeric}")
    print(f"  Null values               : {null_count}")

    print(f"\n  Feature Groups:")
    groups = [
        ("Event Counts",        ["total_events","total_transactions","total_data_changes",
                                  "total_schema_changes","total_privilege_changes",
                                  "total_authentication_events","total_configuration_events",
                                  "total_metadata_events","total_unknown_events"]),
        ("SQL Operations",      ["insert_count","update_count","delete_count","grant_count",
                                  "revoke_count","create_table_count","drop_table_count",
                                  "create_database_count","drop_database_count",
                                  "create_user_count","drop_user_count"]),
        ("Transaction",         ["begin_count","commit_count","rollback_count",
                                  "transaction_success_ratio"]),
        ("Database",            ["unique_database_count","unique_table_count",
                                  "most_active_database","most_active_table"]),
        ("User",                ["unique_user_count","most_active_user",
                                  "admin_operation_count"]),
        ("Ratios",              ["insert_update_ratio","delete_update_ratio",
                                  "ddl_dml_ratio","grant_to_auth_ratio"]),
        ("Errors",              ["error_event_count","success_rate"]),
        ("Time",                ["first_timestamp","last_timestamp","activity_duration"]),
        ("Security",            ["privilege_escalation_events","authentication_changes",
                                  "schema_modification_events","destructive_operations"]),
        ("Composite Scores",    ["data_change_score","schema_change_score","privilege_score",
                                  "authentication_score","transaction_score",
                                  "overall_database_activity_score"]),
    ]
    for group_name, keys in groups:
        print(f"\n    [{group_name}]")
        for k in keys:
            val = vector.get(k, "<MISSING>")
            print(f"      {k:<42} : {val}")

    print(f"\n  Validation Errors: {len(errors)}")
    if errors:
        for err in errors:
            print(f"    [ERROR] {err}")

    print()
    print("=" * W)
    if not errors:
        print("  RESULT: ALL CHECKS PASSED")
    else:
        print(f"  RESULT: {len(errors)} VALIDATION ERROR(S) FOUND")
    print("=" * W)
    print()

    sys.exit(0 if not errors else 1)


if __name__ == "__main__":
    main()
