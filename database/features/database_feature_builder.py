"""
database_feature_builder.py
============================
Stage 3 — Feature Extraction for the Database AI pipeline.

Reads:
    database/normalized/normalized_events.json

Produces a single feature vector (dict) representing the full activity
profile of one database session / audit log.  The vector is stored as:
    database/features/database_feature_vector.json

Design principles
-----------------
* Tool-agnostic: works with any source that produces the standard
  normalized schema (mysqlbinlog, pgAudit, Percona Audit, MariaDB Audit …)
* No SQL text is parsed — only the normalized fields are used.
* Deterministic and reusable: calling extract() twice on the same input
  always produces byte-identical output.
* Mirrors the Memory AI pipeline architecture exactly.

Feature groups
--------------
  1.  Event Counts
  2.  SQL Operation Counts
  3.  Transaction Features
  4.  Database Features
  5.  User Features
  6.  Activity Ratios
  7.  Error Features
  8.  Time Features
  9.  Security Features
  10. Composite / Scoring Features

Usage (as a module)
-------------------
    from features.database_feature_builder import DatabaseFeatureBuilder
    builder = DatabaseFeatureBuilder()
    vector  = builder.extract("database/normalized/normalized_events.json")
    builder.save("database/features/database_feature_vector.json", vector)

Usage (standalone)
------------------
    python features/database_feature_builder.py [--input ...] [--output ...]
"""

import json
import os
import sys
from collections import Counter
from typing import Any, Dict, List, Optional


# ─── Expected feature names (defines the fixed schema order) ──────────────────
# Any future case must produce exactly these features.

FEATURE_SCHEMA = [
    # 1. Event Counts
    "total_events",
    "total_transactions",
    "total_data_changes",
    "total_schema_changes",
    "total_privilege_changes",
    "total_authentication_events",
    "total_configuration_events",
    "total_metadata_events",
    "total_unknown_events",

    # 2. SQL Operation Counts
    "insert_count",
    "update_count",
    "delete_count",
    "replace_count",
    "truncate_count",
    "create_table_count",
    "drop_table_count",
    "alter_table_count",
    "rename_table_count",
    "create_database_count",
    "drop_database_count",
    "create_user_count",
    "drop_user_count",
    "alter_user_count",
    "grant_count",
    "revoke_count",
    "set_password_count",

    # 3. Transaction Features
    "begin_count",
    "commit_count",
    "rollback_count",
    "transaction_success_ratio",

    # 4. Database Features
    "unique_database_count",
    "unique_table_count",
    "most_active_database",   # string
    "most_active_table",      # string

    # 5. User Features
    "unique_user_count",
    "most_active_user",       # string
    "admin_operation_count",

    # 6. Activity Ratios
    "insert_update_ratio",
    "delete_update_ratio",
    "ddl_dml_ratio",
    "grant_to_auth_ratio",

    # 7. Error Features
    "error_event_count",
    "success_rate",

    # 8. Time Features
    "first_timestamp",
    "last_timestamp",
    "activity_duration",

    # 9. Security Features
    "privilege_escalation_events",
    "authentication_changes",
    "schema_modification_events",
    "destructive_operations",

    # 10. Composite / Scoring Features
    "data_change_score",
    "schema_change_score",
    "privilege_score",
    "authentication_score",
    "transaction_score",
    "overall_database_activity_score",
]

# Numeric features (everything except the three categorical strings)
CATEGORICAL_FEATURES = {"most_active_database", "most_active_table", "most_active_user"}
NUMERIC_FEATURES     = [f for f in FEATURE_SCHEMA if f not in CATEGORICAL_FEATURES]


def _safe_ratio(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Return numerator / denominator, or default when denominator is zero."""
    if denominator == 0:
        return default
    return round(numerator / denominator, 6)


def _top(counter: Counter) -> Optional[str]:
    """Return the most common key, or None if the counter is empty."""
    items = counter.most_common(1)
    return items[0][0] if items else None


class DatabaseFeatureBuilder:
    """
    Extracts a fixed-schema feature vector from a normalized_events.json file.
    """

    # ── Public API ─────────────────────────────────────────────────────────────

    def extract(self, input_path: str) -> Dict[str, Any]:
        """
        Load normalized_events.json and return the complete feature dict.
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Normalized events not found: {input_path}")

        with open(input_path, "r", encoding="utf-8") as f:
            events: List[Dict[str, Any]] = json.load(f)

        return self._build_vector(events)

    def save(self, output_path: str, vector: Dict[str, Any]) -> None:
        """Write the feature vector to a JSON file."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(vector, f, indent=4, ensure_ascii=False)

    # ── Internal — helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _count_type(events: List[Dict], et: str) -> int:
        return sum(1 for e in events if e.get("event_type") == et)

    @staticmethod
    def _count_category(events: List[Dict], cat: str) -> int:
        return sum(1 for e in events if e.get("category") == cat)

    # ── Internal — main builder ────────────────────────────────────────────────

    def _build_vector(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        n = len(events)

        # Pre-index counters used across multiple groups
        type_cnt = Counter(e["event_type"] for e in events)
        cat_cnt  = Counter(e["category"]   for e in events)
        db_cnt   = Counter(e["database"]   for e in events if e.get("database"))
        tbl_cnt  = Counter(e["table"]      for e in events if e.get("table"))
        usr_cnt  = Counter(e["user"]       for e in events if e.get("user"))

        # ── Group 1: Event Counts ──────────────────────────────────────────────
        total_events              = n
        total_transactions        = cat_cnt.get("TRANSACTION", 0)
        total_data_changes        = cat_cnt.get("DATA_CHANGE", 0)
        total_schema_changes      = cat_cnt.get("SCHEMA_CHANGE", 0)
        total_privilege_changes   = cat_cnt.get("PRIVILEGE_CHANGE", 0)
        total_authentication_events = cat_cnt.get("AUTHENTICATION", 0)
        total_configuration_events = cat_cnt.get("CONFIGURATION", 0)
        total_metadata_events     = cat_cnt.get("METADATA", 0)
        total_unknown_events      = cat_cnt.get("UNKNOWN", 0)

        # ── Group 2: SQL Operation Counts ──────────────────────────────────────
        insert_count         = type_cnt.get("INSERT", 0)
        update_count         = type_cnt.get("UPDATE", 0)
        delete_count         = type_cnt.get("DELETE", 0)
        replace_count        = type_cnt.get("REPLACE", 0)
        truncate_count       = type_cnt.get("TRUNCATE", 0)
        create_table_count   = type_cnt.get("CREATE_TABLE", 0)
        drop_table_count     = type_cnt.get("DROP_TABLE", 0)
        alter_table_count    = type_cnt.get("ALTER_TABLE", 0)
        rename_table_count   = type_cnt.get("RENAME_TABLE", 0)
        create_database_count = type_cnt.get("CREATE_DATABASE", 0)
        drop_database_count  = type_cnt.get("DROP_DATABASE", 0)
        create_user_count    = type_cnt.get("CREATE_USER", 0)
        drop_user_count      = type_cnt.get("DROP_USER", 0)
        alter_user_count     = type_cnt.get("ALTER_USER", 0)
        grant_count          = type_cnt.get("GRANT", 0)
        revoke_count         = type_cnt.get("REVOKE", 0)
        set_password_count   = type_cnt.get("SET_PASSWORD", 0)

        # ── Group 3: Transaction Features ─────────────────────────────────────
        begin_count    = type_cnt.get("BEGIN", 0)
        commit_count   = type_cnt.get("COMMIT", 0)
        rollback_count = type_cnt.get("ROLLBACK", 0)
        # Ratio: commits / (begins started) — 1.0 means all transactions committed
        transaction_success_ratio = _safe_ratio(commit_count, begin_count)

        # ── Group 4: Database Features ─────────────────────────────────────────
        unique_database_count = len(db_cnt)
        unique_table_count    = len(tbl_cnt)
        most_active_database  = _top(db_cnt)
        most_active_table     = _top(tbl_cnt)

        # ── Group 5: User Features ─────────────────────────────────────────────
        unique_user_count  = len(usr_cnt)
        most_active_user   = _top(usr_cnt)
        # Admin operations: privilege changes + authentication + schema changes
        admin_operation_count = (
            total_privilege_changes
            + total_authentication_events
            + total_schema_changes
        )

        # ── Group 6: Activity Ratios ───────────────────────────────────────────
        dml_count = insert_count + update_count + delete_count + replace_count
        ddl_count = (
            create_table_count + drop_table_count + alter_table_count
            + rename_table_count + create_database_count + drop_database_count
            + truncate_count
        )

        insert_update_ratio = _safe_ratio(insert_count, update_count)
        delete_update_ratio = _safe_ratio(delete_count, update_count)
        ddl_dml_ratio       = _safe_ratio(ddl_count, dml_count)
        grant_to_auth_ratio = _safe_ratio(
            grant_count,
            total_authentication_events if total_authentication_events else 1
        )

        # ── Group 7: Error Features ────────────────────────────────────────────
        error_event_count = sum(
            1 for e in events
            if e.get("error_code") is not None and e.get("error_code") != 0
        )
        success_rate = _safe_ratio(
            sum(1 for e in events if e.get("success") is True), n
        )

        # ── Group 8: Time Features ─────────────────────────────────────────────
        ts_vals = [e["timestamp"] for e in events if e.get("timestamp") is not None]
        first_timestamp   = min(ts_vals) if ts_vals else None
        last_timestamp    = max(ts_vals) if ts_vals else None
        activity_duration = (
            (last_timestamp - first_timestamp) if (first_timestamp and last_timestamp)
            else 0
        )

        # ── Group 9: Security Features ─────────────────────────────────────────
        # Privilege escalation: GRANT events (granting rights to a user)
        privilege_escalation_events = grant_count

        # Authentication changes: CREATE_USER + DROP_USER + ALTER_USER + SET_PASSWORD
        authentication_changes = (
            create_user_count + drop_user_count
            + alter_user_count + set_password_count
        )

        # Schema modification events: all DDL types
        schema_modification_events = (
            create_table_count + drop_table_count + alter_table_count
            + rename_table_count + create_database_count + drop_database_count
            + truncate_count
        )

        # Destructive operations: deletes + drops + truncates
        destructive_operations = (
            delete_count + drop_table_count + drop_database_count
            + truncate_count + drop_user_count
        )

        # ── Group 10: Composite / Scoring Features ─────────────────────────────
        #
        # Each score is a weighted sum designed to surface anomalous levels
        # of activity in that domain.  All weights are tunable without
        # changing the schema — just update the constants below.
        #
        # The scores are intentionally on a natural scale (not normalised)
        # so that an Isolation Forest can learn what "normal" looks like.

        data_change_score = round(
            insert_count    * 1.0
            + update_count  * 1.0
            + delete_count  * 2.0    # deletes carry more weight
            + replace_count * 1.5
            + truncate_count * 5.0,  # truncate is highly destructive
            4,
        )

        schema_change_score = round(
            create_table_count    * 2.0
            + drop_table_count    * 5.0
            + alter_table_count   * 3.0
            + rename_table_count  * 2.0
            + create_database_count * 3.0
            + drop_database_count * 8.0,  # drop db = catastrophic
            4,
        )

        privilege_score = round(
            grant_count         * 3.0
            + revoke_count      * 2.0
            + set_password_count * 4.0,
            4,
        )

        authentication_score = round(
            create_user_count   * 3.0
            + drop_user_count   * 4.0
            + alter_user_count  * 3.0
            + set_password_count * 4.0,
            4,
        )

        transaction_score = round(
            begin_count                           * 0.5
            + commit_count                        * 0.5
            + rollback_count                      * 2.0   # rollbacks are notable
            + (1.0 - transaction_success_ratio)   * 10.0, # uncommitted txns
            4,
        )

        overall_database_activity_score = round(
            data_change_score
            + schema_change_score
            + privilege_score
            + authentication_score
            + (error_event_count * 3.0)
            + (destructive_operations * 1.5),
            4,
        )

        # ── Assemble vector in schema order ────────────────────────────────────
        vector: Dict[str, Any] = {
            # Group 1
            "total_events":                 total_events,
            "total_transactions":           total_transactions,
            "total_data_changes":           total_data_changes,
            "total_schema_changes":         total_schema_changes,
            "total_privilege_changes":      total_privilege_changes,
            "total_authentication_events":  total_authentication_events,
            "total_configuration_events":   total_configuration_events,
            "total_metadata_events":        total_metadata_events,
            "total_unknown_events":         total_unknown_events,
            # Group 2
            "insert_count":          insert_count,
            "update_count":          update_count,
            "delete_count":          delete_count,
            "replace_count":         replace_count,
            "truncate_count":        truncate_count,
            "create_table_count":    create_table_count,
            "drop_table_count":      drop_table_count,
            "alter_table_count":     alter_table_count,
            "rename_table_count":    rename_table_count,
            "create_database_count": create_database_count,
            "drop_database_count":   drop_database_count,
            "create_user_count":     create_user_count,
            "drop_user_count":       drop_user_count,
            "alter_user_count":      alter_user_count,
            "grant_count":           grant_count,
            "revoke_count":          revoke_count,
            "set_password_count":    set_password_count,
            # Group 3
            "begin_count":                begin_count,
            "commit_count":               commit_count,
            "rollback_count":             rollback_count,
            "transaction_success_ratio":  transaction_success_ratio,
            # Group 4
            "unique_database_count": unique_database_count,
            "unique_table_count":    unique_table_count,
            "most_active_database":  most_active_database,
            "most_active_table":     most_active_table,
            # Group 5
            "unique_user_count":    unique_user_count,
            "most_active_user":     most_active_user,
            "admin_operation_count": admin_operation_count,
            # Group 6
            "insert_update_ratio": insert_update_ratio,
            "delete_update_ratio": delete_update_ratio,
            "ddl_dml_ratio":       ddl_dml_ratio,
            "grant_to_auth_ratio": grant_to_auth_ratio,
            # Group 7
            "error_event_count": error_event_count,
            "success_rate":       success_rate,
            # Group 8
            "first_timestamp":   first_timestamp,
            "last_timestamp":    last_timestamp,
            "activity_duration": activity_duration,
            # Group 9
            "privilege_escalation_events":  privilege_escalation_events,
            "authentication_changes":       authentication_changes,
            "schema_modification_events":   schema_modification_events,
            "destructive_operations":       destructive_operations,
            # Group 10
            "data_change_score":               data_change_score,
            "schema_change_score":             schema_change_score,
            "privilege_score":                 privilege_score,
            "authentication_score":            authentication_score,
            "transaction_score":               transaction_score,
            "overall_database_activity_score": overall_database_activity_score,
        }

        return vector


# ─── Standalone entry point ────────────────────────────────────────────────────

def main():
    import argparse

    SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
    DATABASE_DIR = os.path.dirname(SCRIPT_DIR)

    parser = argparse.ArgumentParser(
        description="Database Feature Extractor — Stage 3"
    )
    parser.add_argument(
        "--input", "-i",
        default=os.path.join(DATABASE_DIR, "normalized", "normalized_events.json"),
        help="Path to normalized_events.json",
    )
    parser.add_argument(
        "--output", "-o",
        default=os.path.join(DATABASE_DIR, "features", "database_feature_vector.json"),
        help="Output path for the feature vector JSON",
    )
    args = parser.parse_args()

    print(f"[INFO] Input  : {args.input}")
    print(f"[INFO] Output : {args.output}")
    print()

    builder = DatabaseFeatureBuilder()

    try:
        vector = builder.extract(args.input)
    except Exception as exc:
        print(f"[ERROR] Feature extraction failed: {exc}")
        raise

    builder.save(args.output, vector)
    print(f"[INFO] Written : {args.output}")
    print()

    # ── Print summary ──────────────────────────────────────────────────────────
    numeric_count     = sum(1 for k in vector if k not in CATEGORICAL_FEATURES)
    categorical_count = sum(1 for k in vector if k in CATEGORICAL_FEATURES)
    null_count        = sum(1 for v in vector.values() if v is None)

    print("=" * 42)
    print("  Feature Extraction Summary")
    print("=" * 42)
    print(f"  Events processed     : {vector['total_events']}")
    print(f"  Features generated   : {len(vector)}")
    print(f"  Numeric features     : {numeric_count}")
    print(f"  Categorical features : {categorical_count}")
    print(f"  Null values          : {null_count}")
    print()

    print("  Feature Values:")
    for key in FEATURE_SCHEMA:
        val = vector.get(key)
        print(f"    {key:<40} : {val}")

    print("=" * 42)
    print()


if __name__ == "__main__":
    main()
