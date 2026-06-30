"""
percona_normalizer.py
=====================
Stage 2 — Normalizer for Percona Audit Plugin events.

Input:
    Parsed event dicts produced by percona_parser.PerconaParser

Output:
    database/normalized/normalized_events.json

CRITICAL DESIGN CONTRACT
-------------------------
The output schema is IDENTICAL to the one produced by database_normalizer.py
(the mysqlbinlog normalizer).  This means the existing Feature Extractor
(features/database_feature_builder.py) consumes Percona output unchanged.

Every event contains exactly these fields:
    event_id          int      Sequential 1-based ID
    event_type        str      CREATE_DATABASE, INSERT, GRANT … (same taxonomy)
    category          str      SCHEMA_CHANGE, DATA_CHANGE, PRIVILEGE_CHANGE …
    timestamp         int|null Unix epoch
    server_id         int|null (not available from Percona — always null)
    thread_id         int|null CONNECTION_ID mapped here
    exec_time         int|null (not available from Percona — always null)
    database          str|null Active schema
    table             str|null Table name extracted from SQLTEXT if possible
    user              str|null user@host
    sql               str|null Original SQL statement
    log_position      int|null (not available from Percona — always null)
    end_log_position  int|null (not available from Percona — always null)
    xid               int|null (not available from Percona — always null)
    error_code        int|null STATUS field (0 = success)
    success           bool
    header_type       str|null NAME field (Query, Connect, Quit …)

Fields unavailable in Percona vs mysqlbinlog:
    server_id, exec_time, log_position, end_log_position, xid
    → All set to null (normalizer contract: missing = null, not crash)

Usage (module)
--------------
    from normalization.percona_normalizer import PERCONANormalizer
    norm   = PerconaNormalizer()
    events = norm.normalize_events(parsed_events)
    norm.save("database/normalized/normalized_events.json", events)

Usage (standalone)
------------------
    python normalization/percona_normalizer.py [--input ...] [--output ...]
"""

import argparse
import json
import os
import re
import sys
from collections import Counter
from typing import Any, Dict, List, Optional

# ─── Reuse the same category map and taxonomy from database_normalizer ─────────
# (copied here so this module is self-contained — values are identical)

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
    "LOAD_DATA":       "DATA_CHANGE",
    "SELECT":          "DATA_CHANGE",
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
    "INTVAR":          "CONFIGURATION",
    "USE":             "CONFIGURATION",
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
    "UNKNOWN":         "UNKNOWN",
}

# ─── Table extractor — regex patterns for common DML/DDL ─────────────────────
_TABLE_PATTERNS = [
    re.compile(r'(?:INSERT\s+(?:INTO\s+)?|UPDATE\s+|DELETE\s+FROM\s+|'
               r'REPLACE\s+(?:INTO\s+)?)'
               r'`?([A-Za-z_][\w$]*)`?(?:\.`?([A-Za-z_][\w$]*)`?)?',
               re.IGNORECASE),
    re.compile(r'(?:CREATE|DROP|ALTER|TRUNCATE)\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?'
               r'`?([A-Za-z_][\w$]*)`?(?:\.`?([A-Za-z_][\w$]*)`?)?',
               re.IGNORECASE),
]

_DB_PATTERNS = [
    re.compile(r'(?:CREATE|DROP)\s+(?:DATABASE|SCHEMA)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?'
               r'`?([A-Za-z_][\w$]*)`?', re.IGNORECASE),
    re.compile(r'USE\s+`?([A-Za-z_][\w$]*)`?', re.IGNORECASE),
]


def _extract_table(sql: str, db_context: str) -> tuple:
    """
    Try to extract (database, table) from a SQL statement.
    Returns (db, table) — either may be None.
    """
    if not sql:
        return (None, None)
    for pat in _TABLE_PATTERNS:
        m = pat.search(sql)
        if m:
            g1, g2 = m.group(1), m.group(2) if m.lastindex >= 2 else None
            if g2:
                return (g1, g2)       # schema.table form
            return (None, g1)         # bare table
    return (None, None)


def _extract_db(sql: str) -> Optional[str]:
    """Extract database name from CREATE DATABASE / DROP DATABASE / USE."""
    if not sql:
        return None
    for pat in _DB_PATTERNS:
        m = pat.search(sql)
        if m:
            return m.group(1)
    return None


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

class PerconaNormalizer:
    """
    Converts Percona Audit Parser event dicts into the standard
    normalized schema (identical to mysqlbinlog normalizer output).
    """

    def __init__(self):
        self.errors: List[str] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def normalize_events(
        self, parsed_events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Convert a list of parsed events to the normalized schema."""
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
        """Write normalized events to a JSON file."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, ensure_ascii=False)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _normalize_one(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        operation  = raw.get("operation", "UNKNOWN") or "UNKNOWN"
        event_type = operation  # 1:1 mapping — both use the same taxonomy
        category   = CATEGORY_MAP.get(event_type, "UNKNOWN")

        sql        = _to_str_or_none(raw.get("sql", ""))
        db_context = _to_str_or_none(raw.get("database", ""))

        # Enrich database from SQL when DB field is empty
        if not db_context and sql:
            db_context = _extract_db(sql)

        # Enrich table from SQL (Percona doesn't provide it as a separate field)
        _, table = _extract_table(sql, db_context)
        table = _to_str_or_none(table)

        # For CREATE/DROP DATABASE, set database from SQL
        if event_type in ("CREATE_DATABASE", "DROP_DATABASE") and sql:
            extracted_db = _extract_db(sql)
            if extracted_db:
                db_context = extracted_db

        # thread_id: Percona uses CONNECTION_ID
        thread_id = _to_int_or_none(raw.get("connection_id"))

        # error_code: STATUS (0 = success, non-zero = error)
        error_code = raw.get("status")
        if error_code is not None:
            error_code = _to_int_or_none(error_code)

        success = raw.get("success", True)
        if not isinstance(success, bool):
            success = (error_code == 0) if error_code is not None else True

        return {
            "event_id":         None,         # assigned by caller
            "event_type":       event_type,
            "category":         category,
            "timestamp":        raw.get("timestamp"),        # already int|None
            "server_id":        None,          # not in Percona Audit format
            "thread_id":        thread_id,     # CONNECTION_ID
            "exec_time":        None,          # not in Percona Audit format
            "database":         db_context,
            "table":            table,
            "user":             _to_str_or_none(raw.get("user", "")),
            "sql":              sql,
            "log_position":     None,          # not in Percona Audit format
            "end_log_position": None,          # not in Percona Audit format
            "xid":              None,          # not in Percona Audit format
            "error_code":       error_code,
            "success":          success,
            "header_type":      _to_str_or_none(raw.get("name", "")),
        }


# ─── Summary helpers ──────────────────────────────────────────────────────────

def build_normalization_summary(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    type_counts     = Counter(e["event_type"] for e in events)
    category_counts = Counter(e["category"]   for e in events)
    return {
        "total_events":    len(events),
        "event_types":     dict(sorted(type_counts.items())),
        "categories":      dict(sorted(category_counts.items())),
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
    print("  Normalization Summary")
    print("=" * W)
    print(f"\n  Total Events: {summary['total_events']:,}\n")
    print("  Events by Type:")
    for et, cnt in sorted(summary["event_types"].items()):
        print(f"    {et:<30} : {cnt:,}")
    print("\n  Events by Category:")
    for cat, cnt in sorted(summary["categories"].items()):
        print(f"    {cat:<24} : {cnt:,}")
    print("\n  Missing Fields (null values):")
    for f, cnt in summary["missing_fields"].items():
        print(f"    {f:<24} : {cnt:,}")
    print(f"\n  Normalization Errors: {len(errors)}")
    if errors:
        for e in errors[:5]:
            print(f"    [ERROR] {e}")
    print("=" * W)
    print()


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
    DATABASE_DIR = os.path.dirname(SCRIPT_DIR)

    # Add parser dir to path so we can import percona_parser
    sys.path.insert(0, os.path.join(DATABASE_DIR, "parser"))
    from percona_parser import PerconaParser

    ap = argparse.ArgumentParser(description="Percona Audit Normalizer")
    ap.add_argument("--input", "-i",
                    default=os.path.join(DATABASE_DIR, "audit.log"),
                    help="Path to audit.log (raw Percona XML)")
    ap.add_argument("--output", "-o",
                    default=os.path.join(DATABASE_DIR, "normalized",
                                         "percona_normalized_events.json"),
                    help="Output normalized_events JSON path")
    args = ap.parse_args()

    print(f"[INFO] Input  : {args.input}")
    print(f"[INFO] Output : {args.output}")
    print()

    # ── Parse ─────────────────────────────────────────────────────────────────
    print("[INFO] Stage 1 — Parsing …")
    import time
    t0 = time.time()
    parser = PerconaParser()
    parsed = parser.parse_file(args.input)
    t1 = time.time()
    print(f"[INFO] Parsed {len(parsed):,} events in {t1-t0:.1f}s")
    if parser.errors:
        print(f"[WARN] Parse errors: {len(parser.errors)}")
    print()

    # ── Normalize ─────────────────────────────────────────────────────────────
    print("[INFO] Stage 2 — Normalizing …")
    norm = PerconaNormalizer()
    events = norm.normalize_events(parsed)
    t2 = time.time()
    print(f"[INFO] Normalized {len(events):,} events in {t2-t1:.1f}s")
    print()

    # ── Save ──────────────────────────────────────────────────────────────────
    print(f"[INFO] Writing {args.output} …")
    norm.save(args.output, events)
    print(f"[INFO] Written.")
    print()

    summary = build_normalization_summary(events)
    print_summary(summary, norm.errors)


if __name__ == "__main__":
    main()
