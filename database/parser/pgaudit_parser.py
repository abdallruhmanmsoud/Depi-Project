"""
pgaudit_parser.py
=================
Stage 1 — Parser for pgAudit log files (PostgreSQL audit extension).

Input:
    database/postgresql.log

Output:
    database/raw/pgaudit_parsed_events.txt

pgAudit log line format
-----------------------
Each AUDIT event is a single log line (occasionally multi-line for large SQL):

    2026-06-29 13:06:42.011 UTC [57] LOG:  AUDIT: SESSION,2,1,WRITE,DELETE,TABLE,public.employees,DELETE FROM employees WHERE id=1,<none>

Fields in the CSV payload after "AUDIT: ":
    [0] audit_type     SESSION | OBJECT
    [1] session_id     Integer session counter
    [2] substatement_id
    [3] class          READ | WRITE | DDL | ROLE | FUNCTION | MISC
    [4] command        SELECT | INSERT | UPDATE | DELETE | CREATE TABLE | GRANT …
    [5] object_type    TABLE | VIEW | FUNCTION | "" (empty for DDL/ROLE)
    [6] object_name    schema.table or "" (empty for DDL/ROLE)
    [7] statement      SQL text (may be quoted and contain commas)
    [8] parameter      <none> or parameter info

Design
------
* Line-by-line streaming — never loads the whole file into memory.
* Multi-line SQL (tab-indented continuation lines) are joined correctly.
* Non-AUDIT lines (startup messages, ERROR, STATEMENT) are silently skipped.
* Malformed AUDIT lines are counted and skipped, not crashed on.

Usage (module)
--------------
    from parser.pgaudit_parser import PgAuditParser
    parser = PgAuditParser()
    events = parser.parse_file("database/postgresql.log")

Usage (standalone)
------------------
    python parser/pgaudit_parser.py [--input ...] [--output ...]
"""

import argparse
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple


# ─── Regex: matches the log-line header before the AUDIT: payload ─────────────
# Group 1: timestamp  "2026-06-29 13:06:42.011 UTC"
# Group 2: pid        "57"
# Group 3: severity   "LOG"
# Group 4: payload    "AUDIT: SESSION,2,1,WRITE,DELETE,..."
_LINE_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ UTC) \[(\d+)\] (\w+):\s+AUDIT:\s+(.*)'
)

# Continuation line: starts with a tab (multi-line SQL)
_CONT_RE = re.compile(r'^\t(.*)')


# ─── Command → normalised event_type ──────────────────────────────────────────
# Maps pgAudit command strings to the shared taxonomy used by mysqlbinlog
# and Percona (same CATEGORY_MAP applies downstream).
_COMMAND_MAP: Dict[str, str] = {
    # DML
    "SELECT":            "SELECT",
    "INSERT":            "INSERT",
    "UPDATE":            "UPDATE",
    "DELETE":            "DELETE",
    "COPY":              "INSERT",
    # DDL — tables
    "CREATE TABLE":      "CREATE_TABLE",
    "DROP TABLE":        "DROP_TABLE",
    "ALTER TABLE":       "ALTER_TABLE",
    "TRUNCATE TABLE":    "TRUNCATE",
    "TRUNCATE":          "TRUNCATE",
    # DDL — indexes
    "CREATE INDEX":      "ALTER_TABLE",
    "DROP INDEX":        "ALTER_TABLE",
    "REINDEX":           "ALTER_TABLE",
    # DDL — sequences
    "CREATE SEQUENCE":   "ALTER_TABLE",
    "DROP SEQUENCE":     "ALTER_TABLE",
    "ALTER SEQUENCE":    "ALTER_TABLE",
    # DDL — schema / database
    "CREATE DATABASE":   "CREATE_DATABASE",
    "DROP DATABASE":     "DROP_DATABASE",
    "CREATE SCHEMA":     "CREATE_DATABASE",
    "DROP SCHEMA":       "DROP_DATABASE",
    "CREATE EXTENSION":  "SET",
    # DDL — views
    "CREATE VIEW":       "CREATE_TABLE",
    "DROP VIEW":         "DROP_TABLE",
    # Auth / Privilege (pgAudit ROLE class)
    "CREATE ROLE":       "CREATE_USER",
    "DROP ROLE":         "DROP_USER",
    "ALTER ROLE":        "ALTER_USER",
    "GRANT":             "GRANT",
    "REVOKE":            "REVOKE",
    "SET ROLE":          "SET",
    "REASSIGN OWNED":    "REVOKE",
    "DROP OWNED":        "REVOKE",
    # Transaction
    "BEGIN":             "BEGIN",
    "COMMIT":            "COMMIT",
    "ROLLBACK":          "ROLLBACK",
    "SAVEPOINT":         "SAVEPOINT",
    "RELEASE":           "COMMIT",
    # Configuration / misc
    "SET":               "SET",
    "SHOW":              "SET",
    "RESET":             "SET",
    "LOAD":              "SET",
    # Function / procedure
    "DO":                "DO",
    "CALL":              "DO",
    "EXECUTE":           "DO",
}

# pgAudit CLASS → fallback event_type when command is not in _COMMAND_MAP
_CLASS_FALLBACK: Dict[str, str] = {
    "READ":     "SELECT",
    "WRITE":    "UPDATE",
    "DDL":      "ALTER_TABLE",
    "ROLE":     "GRANT",
    "FUNCTION": "DO",
    "MISC":     "SET",
}

# Summary display order
_SUMMARY_ORDER = [
    "SELECT", "INSERT", "UPDATE", "DELETE",
    "CREATE_DATABASE", "CREATE_TABLE", "ALTER_TABLE", "DROP_TABLE", "TRUNCATE",
    "CREATE_USER", "DROP_USER", "ALTER_USER",
    "GRANT", "REVOKE",
    "BEGIN", "COMMIT", "ROLLBACK",
    "DO", "SET",
    "UNKNOWN",
]


# ─── Timestamp converter ──────────────────────────────────────────────────────

def _ts_to_unix(ts: str) -> Optional[int]:
    """Convert 'YYYY-MM-DD HH:MM:SS.mmm UTC' to Unix epoch int."""
    try:
        dt = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
        return int(dt.replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


# ─── Object-name parser ───────────────────────────────────────────────────────

def _split_object_name(obj: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Split 'schema.table' → (schema, table).
    Returns (None, None) for empty / '<none>'.
    """
    obj = obj.strip()
    if not obj or obj == "<none>":
        return None, None
    if "." in obj:
        parts = obj.split(".", 1)
        return parts[0] or None, parts[1] or None
    return None, obj or None


# ─── CSV splitter that respects quoted fields ─────────────────────────────────

def _split_audit_payload(payload: str) -> List[str]:
    """
    Split an AUDIT payload CSV respecting double-quoted fields.
    Limit to at most 9 fields (last field is the parameter).

    pgAudit CSV format:
        SESSION,session_id,sub_id,class,command,obj_type,obj_name,statement,parameter
    """
    parts: List[str] = []
    current: List[str] = []
    in_quotes = False

    i = 0
    while i < len(payload):
        c = payload[i]
        if c == '"':
            in_quotes = not in_quotes
        elif c == ',' and not in_quotes:
            parts.append("".join(current).strip())
            current = []
            if len(parts) == 8:          # we have all 8 prefix fields
                parts.append(payload[i + 1:].strip())   # rest = parameter
                return parts
            i += 1
            continue
        else:
            current.append(c)
        i += 1

    parts.append("".join(current).strip())
    return parts


# ─── Main Parser ──────────────────────────────────────────────────────────────

class PgAuditParser:
    """Streaming parser for pgAudit PostgreSQL log files."""

    def __init__(self):
        self.errors: List[str] = []
        self.skipped_lines = 0

    def parse_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Parse the log file and return a list of event dicts."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"pgAudit log not found: {filepath}")

        events: List[Dict[str, Any]] = []
        event_id = 0

        # State for multi-line SQL accumulation
        pending: Optional[Dict[str, Any]] = None

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for lineno, raw_line in enumerate(f, 1):
                line = raw_line.rstrip("\r\n")

                # ── Continuation line (tab-indented) ──────────────────────────
                cont_m = _CONT_RE.match(line)
                if cont_m and pending is not None:
                    extra = cont_m.group(1)
                    if pending["sql"]:
                        pending["sql"] += "\n" + extra
                    else:
                        pending["sql"] = extra
                    continue

                # ── Flush any pending multi-line event ────────────────────────
                if pending is not None:
                    event_id += 1
                    pending["event_id"] = event_id
                    events.append(pending)
                    pending = None

                # ── Try to match an AUDIT line ────────────────────────────────
                audit_m = _LINE_RE.match(line)
                if not audit_m:
                    self.skipped_lines += 1
                    continue

                ts_str   = audit_m.group(1)
                pid      = audit_m.group(2)
                severity = audit_m.group(3)
                payload  = audit_m.group(4)

                try:
                    ev = self._parse_payload(payload, ts_str, pid, severity)
                    if ev is None:
                        self.skipped_lines += 1
                        continue
                    pending = ev
                except Exception as exc:
                    self.errors.append(f"Line {lineno}: {exc}")
                    self.skipped_lines += 1

            # ── Flush last pending event ───────────────────────────────────────
            if pending is not None:
                event_id += 1
                pending["event_id"] = event_id
                events.append(pending)

        return events

    def _parse_payload(
        self,
        payload: str,
        ts_str: str,
        pid: str,
        severity: str,
    ) -> Optional[Dict[str, Any]]:
        """Convert one AUDIT payload string into an event dict."""
        parts = _split_audit_payload(payload)
        if len(parts) < 5:
            return None

        audit_type     = parts[0] if len(parts) > 0 else ""
        session_id     = parts[1] if len(parts) > 1 else ""
        substatement_id = parts[2] if len(parts) > 2 else ""
        cls            = parts[3] if len(parts) > 3 else ""
        command        = parts[4] if len(parts) > 4 else ""
        object_type    = parts[5] if len(parts) > 5 else ""
        object_name    = parts[6] if len(parts) > 6 else ""
        statement      = parts[7] if len(parts) > 7 else ""
        parameter      = parts[8] if len(parts) > 8 else ""

        # Derive event_type from command (case-insensitive)
        cmd_upper   = command.strip().upper()
        event_type  = _COMMAND_MAP.get(cmd_upper)
        if event_type is None:
            # Try class fallback
            event_type = _CLASS_FALLBACK.get(cls.strip().upper(), "UNKNOWN")

        # Split object_name → schema + table
        schema, table = _split_object_name(object_name)

        # Clean statement: strip surrounding quotes
        sql = statement.strip()
        if sql.startswith('"') and sql.endswith('"'):
            sql = sql[1:-1].replace('""', '"')
        if sql == "<none>" or sql == "":
            sql = None

        # Status — pgAudit doesn't give per-event status; default success=True
        # We only mark failure when severity != LOG (e.g. ERROR)
        success    = (severity.upper() == "LOG")
        error_code = 0 if success else 1

        return {
            "event_id":       None,          # filled by caller
            "timestamp_raw":  ts_str,
            "timestamp":      _ts_to_unix(ts_str),
            "process_id":     pid,
            "severity":       severity,
            "audit_type":     audit_type,
            "session_id":     session_id,
            "substatement_id": substatement_id,
            "class":          cls,
            "command":        command,
            "object_type":    object_type,
            "object_name":    object_name,
            "schema":         schema,
            "database":       schema,         # pgAudit schema ≈ database context
            "table":          table,
            "sql":            sql,
            "parameter":      parameter if parameter != "<none>" else "",
            "event_type":     event_type,
            "user":           None,           # not available in SESSION audit lines
            "success":        success,
            "error_code":     error_code,
        }


# ─── Text renderer ────────────────────────────────────────────────────────────

def render_events(events: List[Dict[str, Any]], output_path: str) -> None:
    """Write all events to a human-readable text file (same style as other parsers)."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    op_counts = Counter(e["event_type"] for e in events)

    FIELDS = [
        ("Event ID",        "event_id"),
        ("Timestamp",       "timestamp_raw"),
        ("Unix Timestamp",  "timestamp"),
        ("Process ID",      "process_id"),
        ("Severity",        "severity"),
        ("Audit Type",      "audit_type"),
        ("Session ID",      "session_id"),
        ("Sub Statement",   "substatement_id"),
        ("Class",           "class"),
        ("Command",         "command"),
        ("Object Type",     "object_type"),
        ("Object Name",     "object_name"),
        ("Schema",          "schema"),
        ("Table",           "table"),
        ("Event Type",      "event_type"),
        ("Success",         "success"),
        ("SQL",             "sql"),
        ("Parameter",       "parameter"),
    ]

    with open(output_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write("=" * 52 + "\n")
            f.write(f"Event #{ev['event_id']}\n")
            f.write("=" * 52 + "\n\n")
            for label, key in FIELDS:
                val = ev.get(key, "")
                if val is None:
                    val = ""
                if key == "sql" and isinstance(val, str) and len(val) > 300:
                    val = val[:300] + "  ...[truncated]"
                f.write(f"  {label:<18} : {val}\n")
            f.write("\n" + "-" * 52 + "\n\n")

        # Summary
        f.write("\n" + "=" * 52 + "\n")
        f.write("Summary\n")
        f.write("=" * 52 + "\n\n")
        f.write(f"  Total Events  : {len(events):,}\n\n")
        for op in _SUMMARY_ORDER:
            cnt = op_counts.get(op, 0)
            if cnt:
                f.write(f"  {op:<22} : {cnt:,}\n")
        for op, cnt in sorted(op_counts.items()):
            if op not in _SUMMARY_ORDER and cnt:
                f.write(f"  {op:<22} : {cnt:,}\n")
        f.write("\n")


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
    DATABASE_DIR = os.path.dirname(SCRIPT_DIR)

    ap = argparse.ArgumentParser(description="pgAudit PostgreSQL Log Parser")
    ap.add_argument("--input",  "-i",
                    default=os.path.join(DATABASE_DIR, "postgresql.log"))
    ap.add_argument("--output", "-o",
                    default=os.path.join(DATABASE_DIR, "raw", "pgaudit_parsed_events.txt"))
    args = ap.parse_args()

    print(f"[INFO] Input  : {args.input}")
    print(f"[INFO] Output : {args.output}")
    print()

    parser = PgAuditParser()

    print("[INFO] Parsing (streaming) ...")
    import time
    t0 = time.time()
    events = parser.parse_file(args.input)
    elapsed = time.time() - t0

    print(f"[INFO] Parsed {len(events):,} AUDIT events in {elapsed:.1f}s")
    print(f"[INFO] Non-AUDIT lines skipped : {parser.skipped_lines:,}")
    if parser.errors:
        print(f"[WARN] {len(parser.errors)} parse errors:")
        for e in parser.errors[:5]:
            print(f"  {e}")
    print()

    print("[INFO] Writing output ...")
    render_events(events, args.output)
    print(f"[INFO] Written : {args.output}")
    print()

    op_counts = Counter(e["event_type"] for e in events)
    print("=" * 44)
    print("  Parse Summary")
    print("=" * 44)
    print(f"  Total events         : {len(events):,}")
    print(f"  Parse errors         : {len(parser.errors)}")
    print(f"  Non-audit lines skip : {parser.skipped_lines:,}")
    print()
    for op in _SUMMARY_ORDER:
        cnt = op_counts.get(op, 0)
        if cnt:
            print(f"  {op:<22} : {cnt:,}")
    for op, cnt in sorted(op_counts.items()):
        if op not in _SUMMARY_ORDER and cnt:
            print(f"  {op:<22} : {cnt:,}")
    print("=" * 44)
    print()


if __name__ == "__main__":
    main()
