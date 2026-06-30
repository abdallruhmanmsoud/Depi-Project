"""
pgaudit_normalizer.py
=====================
Stage 2 — Normalizer for pgAudit (PostgreSQL) events.

Input:
    Parsed event dicts produced by pgaudit_parser.PgAuditParser

Output:
    database/normalized/pgaudit_normalized_events.json

CRITICAL DESIGN CONTRACT
-------------------------
The output schema is IDENTICAL to database_normalizer.py (mysqlbinlog)
and percona_normalizer.py.  The Feature Extractor works unchanged.

Normalized schema — every event:
    event_id          int
    event_type        str      (shared taxonomy: INSERT, CREATE_TABLE, GRANT …)
    category          str      (SCHEMA_CHANGE, DATA_CHANGE, PRIVILEGE_CHANGE …)
    timestamp         int|null Unix epoch
    server_id         null     (not in pgAudit)
    thread_id         int|null session_id from pgAudit
    exec_time         null     (not in pgAudit)
    database          str|null schema name (pgAudit schema = logical database)
    table             str|null table name
    user              null     (not in SESSION audit lines — no user field)
    sql               str|null SQL statement text
    log_position      null     (not in pgAudit)
    end_log_position  null     (not in pgAudit)
    xid               null     (not in pgAudit)
    error_code        int|null 0 = success
    success           bool
    header_type       str|null class (READ/WRITE/DDL/ROLE/FUNCTION/MISC)

Fields unavailable vs mysqlbinlog:
    server_id, exec_time, log_position, end_log_position, xid, user
    → All null; none consumed by the Feature Extractor.

Usage (module)
--------------
    from normalization.pgaudit_normalizer import PgAuditNormalizer
    norm   = PgAuditNormalizer()
    events = norm.normalize_events(parsed_events)
    norm.save("database/normalized/pgaudit_normalized_events.json", events)

Usage (standalone)
------------------
    python normalization/pgaudit_normalizer.py [--input ...] [--output ...]
"""

import argparse
import json
import os
import sys
from collections import Counter
from typing import Any, Dict, List, Optional

# ─── Reuse the exact same CATEGORY_MAP from the other normalizers ──────────────
CATEGORY_MAP: Dict[str, str] = {
    "CREATE_DATABASE": "SCHEMA_CHANGE",
    "DROP_DATABASE":   "SCHEMA_CHANGE",
    "CREATE_TABLE":    "SCHEMA_CHANGE",
    "DROP_TABLE":      "SCHEMA_CHANGE",
    "ALTER_TABLE":     "SCHEMA_CHANGE",
    "RENAME_TABLE":    "SCHEMA_CHANGE",
    "TRUNCATE":        "SCHEMA_CHANGE",
    "INSERT":          "DATA_CHANGE",
    "UPDATE":          "DATA_CHANGE",
    "DELETE":          "DATA_CHANGE",
    "REPLACE":         "DATA_CHANGE",
    "SELECT":          "DATA_CHANGE",
    "LOAD_DATA":       "DATA_CHANGE",
    "GRANT":           "PRIVILEGE_CHANGE",
    "REVOKE":          "PRIVILEGE_CHANGE",
    "CREATE_USER":     "AUTHENTICATION",
    "DROP_USER":       "AUTHENTICATION",
    "ALTER_USER":      "AUTHENTICATION",
    "SET_PASSWORD":    "AUTHENTICATION",
    "BEGIN":           "TRANSACTION",
    "COMMIT":          "TRANSACTION",
    "ROLLBACK":        "TRANSACTION",
    "SAVEPOINT":       "TRANSACTION",
    "XID":             "TRANSACTION",
    "SET":             "CONFIGURATION",
    "USE":             "CONFIGURATION",
    "INTVAR":          "CONFIGURATION",
    "CONNECT":         "METADATA",
    "DISCONNECT":      "METADATA",
    "LOGIN":           "METADATA",
    "LOGOUT":          "METADATA",
    "BINLOG":          "METADATA",
    "START":           "METADATA",
    "STOP":            "METADATA",
    "ROTATE":          "METADATA",
    "FORMAT_DESCRIPTION": "METADATA",
    "METADATA":        "METADATA",
    # pgAudit-specific
    "DO":              "CONFIGURATION",   # anonymous function blocks
    "UNKNOWN":         "UNKNOWN",
}


def _to_int_or_none(value) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _to_str_or_none(value) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


# ─── Normalizer ───────────────────────────────────────────────────────────────

class PgAuditNormalizer:
    """
    Converts pgAudit parser event dicts to the standard normalized schema
    (identical to mysqlbinlog and Percona normalizers).
    """

    def __init__(self):
        self.errors: List[str] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def normalize_events(
        self, parsed_events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        event_id = 0

        for raw in parsed_events:
            try:
                ev = self._normalize_one(raw)
                if ev is None:
                    continue
                event_id += 1
                ev["event_id"] = event_id
                normalized.append(ev)
            except Exception as exc:
                self.errors.append(
                    f"Event {raw.get('event_id','?')}: {type(exc).__name__}: {exc}"
                )

        return normalized

    def save(self, output_path: str, events: List[Dict[str, Any]]) -> None:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, ensure_ascii=False)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _normalize_one(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_type = raw.get("event_type", "UNKNOWN") or "UNKNOWN"
        category   = CATEGORY_MAP.get(event_type, "UNKNOWN")

        # thread_id: use session_id from pgAudit
        thread_id = _to_int_or_none(raw.get("session_id"))

        # error_code / success
        error_code = raw.get("error_code")
        if isinstance(error_code, bool):
            error_code = 0 if error_code else 1
        error_code = _to_int_or_none(error_code)

        success = raw.get("success", True)
        if not isinstance(success, bool):
            success = (error_code == 0) if error_code is not None else True

        # header_type: use pgAudit class (READ/WRITE/DDL/ROLE/FUNCTION/MISC)
        header_type = _to_str_or_none(raw.get("class"))

        return {
            "event_id":         None,          # assigned by caller
            "event_type":       event_type,
            "category":         category,
            "timestamp":        raw.get("timestamp"),       # int|None
            "server_id":        None,           # not in pgAudit
            "thread_id":        thread_id,      # pgAudit session_id
            "exec_time":        None,           # not in pgAudit
            "database":         _to_str_or_none(raw.get("database")),
            "table":            _to_str_or_none(raw.get("table")),
            "user":             _to_str_or_none(raw.get("user")),
            "sql":              _to_str_or_none(raw.get("sql")),
            "log_position":     None,           # not in pgAudit
            "end_log_position": None,           # not in pgAudit
            "xid":              None,           # not in pgAudit
            "error_code":       error_code,
            "success":          success,
            "header_type":      header_type,
        }


# ─── Summary helpers ──────────────────────────────────────────────────────────

def build_summary(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "total_events":   len(events),
        "event_types":    dict(sorted(Counter(e["event_type"] for e in events).items())),
        "categories":     dict(sorted(Counter(e["category"]   for e in events).items())),
        "missing_fields": {
            "database":  sum(1 for e in events if e["database"]  is None),
            "table":     sum(1 for e in events if e["table"]     is None),
            "user":      sum(1 for e in events if e["user"]      is None),
            "timestamp": sum(1 for e in events if e["timestamp"] is None),
        },
    }


def print_summary(summary: Dict[str, Any], errors: List[str]) -> None:
    W = 44
    print()
    print("=" * W)
    print("  pgAudit Normalization Summary")
    print("=" * W)
    print(f"\n  Total Events: {summary['total_events']:,}\n")
    print("  Events by Type:")
    for et, cnt in sorted(summary["event_types"].items(), key=lambda x: -x[1]):
        print(f"    {et:<30} : {cnt:,}")
    print("\n  Events by Category:")
    for cat, cnt in sorted(summary["categories"].items(), key=lambda x: -x[1]):
        print(f"    {cat:<26} : {cnt:,}")
    print("\n  Missing Fields (null values):")
    for f, cnt in summary["missing_fields"].items():
        print(f"    {f:<24} : {cnt:,}")
    print(f"\n  Normalization Errors: {len(errors)}")
    if errors:
        for e in errors[:5]:
            print(f"    [ERROR] {e}")
    print("=" * W)
    print()


# ─── Validation ───────────────────────────────────────────────────────────────

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

ALWAYS_NULL_IN_PGAUDIT = {
    "server_id", "exec_time", "log_position", "end_log_position", "xid", "user"
}


def validate_events(events: List[Dict[str, Any]]) -> List[str]:
    errors = []
    seen_ids = set()
    for i, ev in enumerate(events):
        eid = ev.get("event_id", f"<missing@{i}>")
        p   = f"Event #{eid}"
        for field in REQUIRED_FIELDS:
            if field not in ev:
                errors.append(f"{p}: missing field '{field}'")
        if eid in seen_ids:
            errors.append(f"{p}: duplicate event_id")
        else:
            seen_ids.add(eid)
        et = ev.get("event_type")
        if not isinstance(et, str) or not et.strip():
            errors.append(f"{p}: invalid event_type: {repr(et)}")
        if ev.get("category") not in VALID_CATEGORIES:
            errors.append(f"{p}: unrecognised category: {repr(ev.get('category'))}")
        if not isinstance(ev.get("success"), bool):
            errors.append(f"{p}: success not bool")
        ec = ev.get("error_code")
        if ec is not None and not isinstance(ec, int):
            errors.append(f"{p}: error_code not int/null")
        ts = ev.get("timestamp")
        if ts is not None and not isinstance(ts, int):
            errors.append(f"{p}: timestamp not int/null")
    return errors


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
    DATABASE_DIR = os.path.dirname(SCRIPT_DIR)

    sys.path.insert(0, os.path.join(DATABASE_DIR, "parser"))
    from pgaudit_parser import PgAuditParser

    ap = argparse.ArgumentParser(description="pgAudit Normalizer")
    ap.add_argument("--input", "-i",
                    default=os.path.join(DATABASE_DIR, "postgresql.log"))
    ap.add_argument("--output", "-o",
                    default=os.path.join(DATABASE_DIR, "normalized",
                                         "pgaudit_normalized_events.json"))
    args = ap.parse_args()

    print(f"[INFO] Input  : {args.input}")
    print(f"[INFO] Output : {args.output}")
    print()

    # ── Stage 1: Parse ────────────────────────────────────────────────────────
    import time
    print("[INFO] Stage 1 -- Parsing ...")
    t0 = time.time()
    parser = PgAuditParser()
    parsed = parser.parse_file(args.input)
    t1 = time.time()
    print(f"[INFO] Parsed {len(parsed):,} events in {t1-t0:.1f}s")
    if parser.errors:
        print(f"[WARN] Parse errors: {len(parser.errors)}")
    print()

    # ── Stage 2: Normalize ────────────────────────────────────────────────────
    print("[INFO] Stage 2 -- Normalizing ...")
    norm   = PgAuditNormalizer()
    events = norm.normalize_events(parsed)
    t2 = time.time()
    print(f"[INFO] Normalized {len(events):,} events in {t2-t1:.1f}s")
    print()

    # ── Validate ──────────────────────────────────────────────────────────────
    print("[INFO] Validating ...")
    val_errors = validate_events(events)
    print(f"[INFO] Validation errors: {len(val_errors)}")
    if val_errors:
        for e in val_errors[:10]:
            print(f"  [ERROR] {e}")
    print()

    # ── Save ──────────────────────────────────────────────────────────────────
    print(f"[INFO] Writing {args.output} ...")
    norm.save(args.output, events)
    print(f"[INFO] Written.")

    summary = build_summary(events)
    print_summary(summary, norm.errors)

    if val_errors:
        print(f"[FAIL] {len(val_errors)} validation errors found.")
        sys.exit(1)
    else:
        print("[OK] All checks passed.")


if __name__ == "__main__":
    main()
