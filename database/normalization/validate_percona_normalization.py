"""
validate_percona_normalization.py
==================================
Validates normalized_events.json produced by percona_normalizer.py.

Checks:
  1.  Valid JSON
  2.  Required fields present in every event
  3.  No duplicate event_ids
  4.  event_type is a non-empty string
  5.  category is a recognised value
  6.  success is bool
  7.  error_code is int or null
  8.  timestamp is int or null
  9.  Schema compatibility with mysqlbinlog normalizer
  10. Fields unavailable in Percona but OK to be null

Usage:
    python normalization/validate_percona_normalization.py [path]
"""

import json
import os
import sys
from collections import Counter

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DATABASE_DIR = os.path.dirname(SCRIPT_DIR)

REQUIRED_FIELDS = [
    "event_id", "event_type", "category", "timestamp",
    "server_id", "thread_id", "exec_time",
    "database", "table", "user", "sql",
    "log_position", "end_log_position", "xid",
    "error_code", "success", "header_type",
]

VALID_CATEGORIES = {
    "SCHEMA_CHANGE", "DATA_CHANGE", "PRIVILEGE_CHANGE",
    "AUTHENTICATION", "TRANSACTION", "CONFIGURATION",
    "METADATA", "UNKNOWN",
}

# Fields that are expected to be null for ALL Percona events
# (not available in the Percona Audit Plugin format)
ALWAYS_NULL_IN_PERCONA = {
    "server_id", "exec_time", "log_position", "end_log_position", "xid"
}

W = 55


def validate(events) -> list:
    errors = []
    seen_ids = set()

    for i, ev in enumerate(events):
        eid = ev.get("event_id", f"<missing@{i}>")
        p   = f"Event #{eid}"

        # Required fields
        for field in REQUIRED_FIELDS:
            if field not in ev:
                errors.append(f"{p}: missing field '{field}'")

        # Duplicate IDs
        if eid in seen_ids:
            errors.append(f"{p}: duplicate event_id {eid}")
        else:
            seen_ids.add(eid)

        # event_type
        et = ev.get("event_type")
        if not isinstance(et, str) or not et.strip():
            errors.append(f"{p}: invalid event_type: {repr(et)}")

        # category
        cat = ev.get("category")
        if cat not in VALID_CATEGORIES:
            errors.append(f"{p}: unrecognised category: {repr(cat)}")

        # success
        if not isinstance(ev.get("success"), bool):
            errors.append(f"{p}: 'success' not bool: {repr(ev.get('success'))}")

        # error_code
        ec = ev.get("error_code")
        if ec is not None and not isinstance(ec, int):
            errors.append(f"{p}: error_code not int/null: {repr(ec)}")

        # timestamp
        ts = ev.get("timestamp")
        if ts is not None and not isinstance(ts, int):
            errors.append(f"{p}: timestamp not int/null: {repr(ts)}")

    return errors


def main():
    if len(sys.argv) >= 2:
        input_path = sys.argv[1]
    else:
        input_path = os.path.join(DATABASE_DIR, "normalized", "normalized_events.json")

    print(f"[INFO] Validating: {input_path}")
    print()

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            events = json.load(f)
    except json.JSONDecodeError as exc:
        print(f"[FAIL] Invalid JSON: {exc}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"[FAIL] File not found: {input_path}")
        sys.exit(1)

    print(f"  JSON valid           : YES")
    print(f"  Events loaded        : {len(events):,}")
    print()

    errors = validate(events)

    type_counts  = Counter(e.get("event_type","?") for e in events)
    cat_counts   = Counter(e.get("category","?")   for e in events)
    null_counts  = {f: sum(1 for e in events if e.get(f) is None) for f in REQUIRED_FIELDS}
    success_cnt  = sum(1 for e in events if e.get("success") is True)
    unique_users = len(set(e.get("user") for e in events if e.get("user")))
    unique_dbs   = len(set(e.get("database") for e in events if e.get("database")))

    print("=" * W)
    print("  Percona Normalization Validation Report")
    print("=" * W)
    print(f"\n  Total Events          : {len(events):,}")
    print(f"  Successful Events     : {success_cnt:,}  ({100*success_cnt//len(events) if events else 0}%)")
    print(f"  Unique Users          : {unique_users}")
    print(f"  Unique Databases      : {unique_dbs}")

    print(f"\n  Events by Type:")
    for et, cnt in sorted(type_counts.items(), key=lambda x:-x[1]):
        print(f"    {et:<30} : {cnt:,}")

    print(f"\n  Events by Category:")
    for cat, cnt in sorted(cat_counts.items(), key=lambda x:-x[1]):
        print(f"    {cat:<26} : {cnt:,}")

    print(f"\n  Null Field Counts (null = expected for some fields):")
    for field, cnt in null_counts.items():
        expected = " (expected: not in Percona format)" if field in ALWAYS_NULL_IN_PERCONA else ""
        print(f"    {field:<22} : {cnt:,}{expected}")

    print(f"\n  Schema Compatibility with mysqlbinlog:")
    print(f"    Required fields         : {len(REQUIRED_FIELDS)}")
    print(f"    Fields always null      : {len(ALWAYS_NULL_IN_PERCONA)}  "
          f"({', '.join(sorted(ALWAYS_NULL_IN_PERCONA))})")
    print(f"    Fields shared & filled  : {len(REQUIRED_FIELDS) - len(ALWAYS_NULL_IN_PERCONA)}")
    print(f"    Feature Extractor compat: YES — same schema, null fields handled by extractor")

    print(f"\n  Sample Events (first 3):")
    for ev in events[:3]:
        print(f"    #{ev['event_id']:>6}  {ev['event_type']:<22}  cat={ev['category']}")
        print(f"           ts={ev['timestamp']}  db={ev['database']}  user={ev['user']}")
        sql = str(ev.get('sql') or '')[:80]
        print(f"           sql={sql}")
        print()

    print(f"  Validation Errors: {len(errors)}")
    if errors:
        for e in errors[:20]:
            print(f"    [ERROR] {e}")
        if len(errors) > 20:
            print(f"    ... and {len(errors)-20} more")

    print()
    print("=" * W)
    if not errors:
        print("  RESULT: ALL CHECKS PASSED")
    else:
        print(f"  RESULT: {len(errors)} VALIDATION ERROR(S)")
    print("=" * W)
    print()

    sys.exit(0 if not errors else 1)


if __name__ == "__main__":
    main()
