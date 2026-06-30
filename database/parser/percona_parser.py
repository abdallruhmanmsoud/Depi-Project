"""
percona_parser.py
=================
Stage 1 — Parser for the Percona Audit Plugin XML log.

Input:
    database/audit.log

Output:
    database/raw/percona_parsed_events.txt

The Percona Audit Plugin produces XML like:

    <AUDIT_RECORD
      NAME="Query"
      RECORD="6_2026-06-28T16:31:46"
      TIMESTAMP="2026-06-28T16:37:38Z"
      COMMAND_CLASS="select"
      CONNECTION_ID="91762"
      STATUS="0"
      SQLTEXT="select @@version_comment limit 1"
      USER="root[root] @ localhost []"
      HOST="localhost"
      OS_USER=""
      IP=""
      DB=""
    />

Design
------
* Streaming line-by-line reader — never loads the whole file into memory.
* Works with multi-GB files.
* Resilient: malformed or incomplete records are skipped and logged.
* The file often has no closing </AUDIT> tag (common for live/truncated logs);
  this is handled gracefully.
* Tool-agnostic output format matches the mysqlbinlog parser exactly.

Extracted fields per event
--------------------------
    record_id       RECORD attribute (e.g. "6_2026-06-28T16:31:46")
    timestamp       TIMESTAMP attribute (ISO-8601 string)
    name            NAME attribute  (Query, Connect, Quit, Audit, Init DB …)
    command_class   COMMAND_CLASS attribute (insert, update, select …)
    connection_id   CONNECTION_ID
    status          STATUS (0 = success)
    sql             SQLTEXT
    user            USER (e.g. "root[root] @ localhost []")
    priv_user       PRIV_USER
    host            HOST
    ip              IP
    os_user         OS_USER
    os_login        OS_LOGIN
    proxy_user      PROXY_USER
    database        DB
    mysql_version   MYSQL_VERSION  (Audit record only)
    startup_options STARTUP_OPTIONS
    os_version      OS_VERSION

Usage (module)
--------------
    from parser.percona_parser import PerconaParser
    parser = PerconaParser()
    events = parser.parse_file("database/audit.log")

Usage (standalone)
------------------
    python parser/percona_parser.py [--input ...] [--output ...]
"""

import argparse
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

# ─── Attribute regex — matches:  KEY="value"  inside a AUDIT_RECORD block ─────
_ATTR_RE = re.compile(r'([A-Z_]+)="([^"]*)"')

# Fields that may contain embedded double-quotes — we handle them separately
# (Percona escapes them as &quot; but sometimes they slip through)

# ─── Command-class → normalised operation type ────────────────────────────────
_COMMAND_TO_OP = {
    # DML
    "select":          "SELECT",
    "insert":          "INSERT",
    "update":          "UPDATE",
    "delete":          "DELETE",
    "replace":         "REPLACE",
    "load":            "LOAD_DATA",
    # DDL
    "create_table":    "CREATE_TABLE",
    "drop_table":      "DROP_TABLE",
    "alter_table":     "ALTER_TABLE",
    "rename_table":    "RENAME_TABLE",
    "truncate":        "TRUNCATE",
    "create_db":       "CREATE_DATABASE",
    "drop_db":         "DROP_DATABASE",
    "create_index":    "ALTER_TABLE",
    "drop_index":      "ALTER_TABLE",
    # Auth / Privilege
    "create_user":     "CREATE_USER",
    "drop_user":       "DROP_USER",
    "alter_user":      "ALTER_USER",
    "rename_user":     "ALTER_USER",
    "set_password":    "SET_PASSWORD",
    "grant":           "GRANT",
    "revoke":          "REVOKE",
    "revoke_all":      "REVOKE",
    # Session
    "init db":         "USE",
    "change_db":       "USE",
    # Transaction
    "begin":           "BEGIN",
    "commit":          "COMMIT",
    "rollback":        "ROLLBACK",
    "savepoint":       "SAVEPOINT",
    # Configuration
    "set_option":      "SET",
    "show_variables":  "SET",
    "show_status":     "SET",
    "show_plugins":    "SET",
    "install_plugin":  "SET",
    "uninstall_plugin":"SET",
    "flush":           "SET",
    # Connection events (from NAME, not COMMAND_CLASS)
    "connect":         "CONNECT",
    "disconnect":      "DISCONNECT",
    "quit":            "DISCONNECT",
    "login":           "LOGIN",
    "logout":          "LOGOUT",
    # Error
    "error":           "UNKNOWN",
}

# NAME → operation for non-Query records
_NAME_TO_OP = {
    "Connect":  "CONNECT",
    "Quit":     "DISCONNECT",
    "Init DB":  "USE",
    "Audit":    "METADATA",
    "NoAudit":  "METADATA",
}

# Summary categories — which operation types go into which summary bucket
_SUMMARY_ORDER = [
    "SELECT", "INSERT", "UPDATE", "DELETE",
    "CREATE_DATABASE", "CREATE_TABLE", "ALTER_TABLE", "DROP_TABLE",
    "CREATE_USER", "DROP_USER", "GRANT", "REVOKE",
    "LOGIN", "LOGOUT", "CONNECT", "DISCONNECT",
    "REPLACE", "TRUNCATE", "RENAME_TABLE", "ALTER_USER", "SET_PASSWORD",
    "USE", "SET", "BEGIN", "COMMIT", "ROLLBACK",
    "METADATA", "UNKNOWN",
]


# ─── Streaming block reader ────────────────────────────────────────────────────

def _iter_record_blocks(filepath: str) -> Iterator[str]:
    """
    Yield each complete <AUDIT_RECORD ... /> block as a single string.
    Handles:
      - Multi-line records (attributes on separate lines)
      - Self-closing />
      - File with no closing </AUDIT> tag
      - UTF-8 with replacement for any encoding errors
    """
    in_record = False
    lines: List[str] = []

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\r\n")

            if "<AUDIT_RECORD" in line:
                in_record = True
                lines = [line]
                # Self-closing on same line?
                if "/>" in line[line.index("<AUDIT_RECORD"):]:
                    yield " ".join(lines)
                    in_record = False
                    lines = []
                continue

            if in_record:
                lines.append(line)
                if "/>" in line or "</AUDIT_RECORD>" in line:
                    yield " ".join(lines)
                    in_record = False
                    lines = []


# ─── Attribute extractor ──────────────────────────────────────────────────────

def _parse_attrs(block: str) -> Dict[str, str]:
    """Extract all KEY="value" pairs from a record block string."""
    return {m.group(1): m.group(2) for m in _ATTR_RE.finditer(block)}


# ─── User field parser ────────────────────────────────────────────────────────

def _parse_user_field(raw_user: str) -> str:
    """
    Percona USER field looks like: "root[root] @ localhost []"
    Extract the canonical  user@host  form.
    """
    if not raw_user:
        return ""
    # Try "user[priv] @ host [ip]" pattern
    m = re.match(r"^(\w[\w$]*)\[[\w$]*\]\s*@\s*([\w.\-]+)", raw_user)
    if m:
        return f"{m.group(1)}@{m.group(2)}"
    # Fallback: return as-is (trimmed)
    return raw_user.strip()


# ─── Timestamp converter ──────────────────────────────────────────────────────

def _iso_to_unix(ts: str) -> Optional[int]:
    """Convert ISO-8601 timestamp string to Unix epoch integer."""
    if not ts:
        return None
    try:
        # "2026-06-28T16:37:38Z"
        dt = datetime.strptime(ts.rstrip("Z"), "%Y-%m-%dT%H:%M:%S")
        return int(dt.replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


# ─── Main Parser ──────────────────────────────────────────────────────────────

class PerconaParser:
    """
    Streaming parser for Percona Audit Plugin XML logs.
    """

    def __init__(self):
        self.errors: List[str] = []

    def parse_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Parse audit.log and return a list of event dicts.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Audit log not found: {filepath}")

        events: List[Dict[str, Any]] = []
        event_id = 0

        for block in _iter_record_blocks(filepath):
            try:
                ev = self._parse_block(block)
                if ev is None:
                    continue
                event_id += 1
                ev["event_id"] = event_id
                events.append(ev)
            except Exception as exc:
                self.errors.append(f"Block {event_id + 1}: {exc}")

        return events

    def _parse_block(self, block: str) -> Optional[Dict[str, Any]]:
        """Convert one record block string into an event dict."""
        attrs = _parse_attrs(block)
        if not attrs:
            return None

        name          = attrs.get("NAME", "")
        command_class = attrs.get("COMMAND_CLASS", "").lower()
        raw_user      = attrs.get("USER", "")
        timestamp_raw = attrs.get("TIMESTAMP", "")
        status_raw    = attrs.get("STATUS", "")

        # Derive operation type
        operation = _COMMAND_TO_OP.get(command_class, "")
        if not operation:
            operation = _NAME_TO_OP.get(name, "UNKNOWN")

        # Parse user
        user = _parse_user_field(raw_user)
        if not user:
            user = attrs.get("PRIV_USER", "")

        # Status / success
        try:
            status = int(status_raw) if status_raw != "" else None
        except ValueError:
            status = None
        success = (status == 0) if status is not None else True

        return {
            "event_id":       None,          # filled by caller
            "record_id":      attrs.get("RECORD", ""),
            "timestamp_raw":  timestamp_raw,
            "timestamp":      _iso_to_unix(timestamp_raw),
            "name":           name,
            "command_class":  command_class,
            "operation":      operation,
            "connection_id":  attrs.get("CONNECTION_ID", ""),
            "status":         status,
            "success":        success,
            "sql":            attrs.get("SQLTEXT", ""),
            "user":           user,
            "raw_user":       raw_user,
            "priv_user":      attrs.get("PRIV_USER", ""),
            "host":           attrs.get("HOST", ""),
            "ip":             attrs.get("IP", ""),
            "os_user":        attrs.get("OS_USER", ""),
            "os_login":       attrs.get("OS_LOGIN", ""),
            "proxy_user":     attrs.get("PROXY_USER", ""),
            "database":       attrs.get("DB", ""),
            "mysql_version":  attrs.get("MYSQL_VERSION", ""),
            "startup_options": attrs.get("STARTUP_OPTIONS", ""),
            "os_version":     attrs.get("OS_VERSION", ""),
        }


# ─── Text renderer ────────────────────────────────────────────────────────────

def render_events(events: List[Dict[str, Any]], output_path: str) -> None:
    """Write all events + summary to a human-readable text file."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    op_counts = Counter(e["operation"] for e in events)

    FIELDS = [
        ("Event ID",       "event_id"),
        ("Record ID",      "record_id"),
        ("Timestamp",      "timestamp_raw"),
        ("Unix Timestamp", "timestamp"),
        ("Name",           "name"),
        ("Command Class",  "command_class"),
        ("Operation",      "operation"),
        ("Connection ID",  "connection_id"),
        ("Status",         "status"),
        ("Success",        "success"),
        ("User",           "user"),
        ("Host",           "host"),
        ("IP",             "ip"),
        ("Database",       "database"),
        ("OS User",        "os_user"),
        ("SQL",            "sql"),
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
                # Truncate very long SQL for readability (keep first 300 chars)
                if key == "sql" and isinstance(val, str) and len(val) > 300:
                    val = val[:300] + "  ...[truncated]"
                f.write(f"  {label:<18} : {val}\n")
            f.write("\n" + "-" * 52 + "\n\n")

        # ── Summary ────────────────────────────────────────────────────────────
        f.write("\n" + "=" * 52 + "\n")
        f.write("Summary\n")
        f.write("=" * 52 + "\n\n")
        f.write(f"  Total Events  : {len(events)}\n\n")
        for op in _SUMMARY_ORDER:
            cnt = op_counts.get(op, 0)
            f.write(f"  {op:<22} : {cnt}\n")
        # Any unlisted types
        for op, cnt in sorted(op_counts.items()):
            if op not in _SUMMARY_ORDER:
                f.write(f"  {op:<22} : {cnt}\n")
        f.write("\n")


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
    DATABASE_DIR = os.path.dirname(SCRIPT_DIR)

    ap = argparse.ArgumentParser(description="Percona Audit Plugin XML Parser")
    ap.add_argument("--input",  "-i",
                    default=os.path.join(DATABASE_DIR, "audit.log"))
    ap.add_argument("--output", "-o",
                    default=os.path.join(DATABASE_DIR, "raw", "percona_parsed_events.txt"))
    args = ap.parse_args()

    print(f"[INFO] Input  : {args.input}")
    print(f"[INFO] Output : {args.output}")
    print()

    parser = PerconaParser()

    print("[INFO] Parsing (streaming) …")
    t0 = __import__("time").time()
    events = parser.parse_file(args.input)
    elapsed = __import__("time").time() - t0

    print(f"[INFO] Parsed {len(events):,} events in {elapsed:.1f}s")
    if parser.errors:
        print(f"[WARN] {len(parser.errors)} parse errors (first 5):")
        for e in parser.errors[:5]:
            print(f"  {e}")
    print()

    print("[INFO] Writing output …")
    render_events(events, args.output)
    print(f"[INFO] Written : {args.output}")
    print()

    # Console summary
    op_counts = Counter(e["operation"] for e in events)
    print("=" * 42)
    print("  Parse Summary")
    print("=" * 42)
    print(f"  Total events : {len(events):,}")
    print(f"  Parse errors : {len(parser.errors)}")
    print()
    for op in _SUMMARY_ORDER:
        cnt = op_counts.get(op, 0)
        if cnt:
            print(f"  {op:<22} : {cnt:,}")
    print("=" * 42)
    print()


if __name__ == "__main__":
    main()
