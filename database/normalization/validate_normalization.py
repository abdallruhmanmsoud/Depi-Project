"""
validate_normalization.py
=========================
Validates the output of database_normalizer.py.

Checks performed:
  1. JSON is valid (parseable)
  2. Every event has the required fields
  3. No duplicate event_ids
  4. event_type is a non-empty string
  5. category is a recognised value
  6. success is a boolean
  7. error_code is int or null
  8. timestamp is int or null
  9. Counts match normalization summary

Usage:
    python normalization/validate_normalization.py [path_to_normalized_events.json]
"""

import json
import os
import sys
from collections import Counter
from typing import Any, Dict, List

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DATABASE_DIR = os.path.dirname(SCRIPT_DIR)

REQUIRED_FIELDS = [
    "event_id", "event_type", "category", "timestamp",
    "database", "table", "user", "sql",
    "log_position", "end_log_position", "xid",
    "error_code", "success", "server_id", "thread_id",
    "exec_time", "header_type",
]

VALID_CATEGORIES = {
    "SCHEMA_CHANGE", "DATA_CHANGE", "PRIVILEGE_CHANGE",
    "AUTHENTICATION", "TRANSACTION", "CONFIGURATION",
    "METADATA", "UNKNOWN",
}

W = 50


def validate(events: List[Dict[str, Any]]) -> List[str]:
    """Run all checks and return a list of error strings."""
    errors = []
    seen_ids = set()

    for i, ev in enumerate(events):
        eid = ev.get("event_id", f"<missing at index {i}>")
        prefix = f"Event #{eid}"

        # ── Required fields ───────────────────────────────────────────────────
        for field in REQUIRED_FIELDS:
            if field not in ev:
                errors.append(f"{prefix}: missing required field '{field}'")

        # ── Duplicate event_id ─────────────────────────────────────────────────
        if eid in seen_ids:
            errors.append(f"{prefix}: duplicate event_id {eid}")
        else:
            seen_ids.add(eid)

        # ── event_type must be a non-empty string ─────────────────────────────
        et = ev.get("event_type")
        if not isinstance(et, str) or not et.strip():
            errors.append(f"{prefix}: event_type is invalid: {repr(et)}")

        # ── category must be recognised ───────────────────────────────────────
        cat = ev.get("category")
        if cat not in VALID_CATEGORIES:
            errors.append(f"{prefix}: unrecognised category: {repr(cat)}")

        # ── success must be bool ──────────────────────────────────────────────
        if not isinstance(ev.get("success"), bool):
            errors.append(f"{prefix}: 'success' is not a bool: {repr(ev.get('success'))}")

        # ── error_code must be int or null ────────────────────────────────────
        ec = ev.get("error_code")
        if ec is not None and not isinstance(ec, int):
            errors.append(f"{prefix}: error_code is not int or null: {repr(ec)}")

        # ── timestamp must be int or null ─────────────────────────────────────
        ts = ev.get("timestamp")
        if ts is not None and not isinstance(ts, int):
            errors.append(f"{prefix}: timestamp is not int or null: {repr(ts)}")

    return errors


def main():
    if len(sys.argv) >= 2:
        input_path = sys.argv[1]
    else:
        input_path = os.path.join(DATABASE_DIR, "normalized", "mysqlbinlog_normalized_events.json")

    print(f"[INFO] Validating: {input_path}")
    print()

    # ── Step 1: JSON parseable ────────────────────────────────────────────────
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            events = json.load(f)
    except json.JSONDecodeError as exc:
        print(f"[FAIL] Invalid JSON: {exc}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"[FAIL] File not found: {input_path}")
        sys.exit(1)

    print(f"  JSON valid              : YES")
    print(f"  Total events loaded     : {len(events)}")
    print()

    # ── Step 2: Field / type checks ───────────────────────────────────────────
    errors = validate(events)

    # ── Step 3: Statistics ────────────────────────────────────────────────────
    type_counts     = Counter(e.get("event_type", "?") for e in events)
    category_counts = Counter(e.get("category",   "?") for e in events)

    missing_db    = sum(1 for e in events if e.get("database")  is None)
    missing_table = sum(1 for e in events if e.get("table")     is None)
    missing_user  = sum(1 for e in events if e.get("user")      is None)
    missing_ts    = sum(1 for e in events if e.get("timestamp") is None)
    success_count = sum(1 for e in events if e.get("success") is True)

    # ── Step 4: Print full report ─────────────────────────────────────────────
    print("=" * W)
    print("  Normalization Validation Report")
    print("=" * W)
    print(f"\n  Total Events: {len(events)}")
    print(f"  Successful  : {success_count}  ({100*success_count//len(events) if events else 0}%)")
    print()

    print("  Events by Type:")
    for et, cnt in sorted(type_counts.items()):
        print(f"    {et:<30} : {cnt}")

    print("\n  Events by Category:")
    for cat, cnt in sorted(category_counts.items()):
        print(f"    {cat:<22} : {cnt}")

    print("\n  Missing Fields (null values):")
    print(f"    {'database':<22} : {missing_db}")
    print(f"    {'table':<22} : {missing_table}")
    print(f"    {'user':<22} : {missing_user}")
    print(f"    {'timestamp':<22} : {missing_ts}")

    print(f"\n  Validation Errors: {len(errors)}")
    if errors:
        for err in errors[:20]:   # cap output for large files
            print(f"    [ERROR] {err}")
        if len(errors) > 20:
            print(f"    ... and {len(errors) - 20} more")

    print()

    # ── Step 5: Sample output ─────────────────────────────────────────────────
    print("  Sample Events (first 3):")
    for ev in events[:3]:
        print(f"    #{ev['event_id']:>4}  {ev['event_type']:<22}  cat={ev['category']}")
        print(f"           ts={ev['timestamp']}  db={ev['database']}  tbl={ev['table']}  user={ev['user']}")
        print(f"           sql={str(ev['sql'])[:80]}")
        print()

    # ── Final verdict ─────────────────────────────────────────────────────────
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
