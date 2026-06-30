"""
database_normalizer.py
======================
Converts the human-readable parsed_events.txt (produced by mysqlbinlog_parser.py)
into a clean, tool-agnostic JSON schema stored in normalized_events.json.

The output schema is intentionally independent of mysqlbinlog so that future
audit log sources (pgAudit, Percona Audit, MariaDB Audit, etc.) can feed the
same Feature Extractor without any changes downstream.

Usage (as a module):
    from normalization.database_normalizer import DatabaseNormalizer
    norm = DatabaseNormalizer()
    events = norm.normalize_file("database/raw/parsed_events.txt")
    norm.save("database/normalized/normalized_events.json", events)

Usage (standalone):
    python normalization/database_normalizer.py \\
        --input  database/raw/parsed_events.txt \\
        --output database/normalized/normalized_events.json
"""

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional


# ═══════════════════════════════════════════════════════════════════════════════
#  CATEGORY MAP
#  Maps each parser event_type to a high-level analytic category.
# ═══════════════════════════════════════════════════════════════════════════════

CATEGORY_MAP: Dict[str, str] = {
    # SCHEMA_CHANGE
    "CREATE_DATABASE": "SCHEMA_CHANGE",
    "DROP_DATABASE":   "SCHEMA_CHANGE",
    "CREATE_TABLE":    "SCHEMA_CHANGE",
    "DROP_TABLE":      "SCHEMA_CHANGE",
    "ALTER_TABLE":     "SCHEMA_CHANGE",
    "RENAME_TABLE":    "SCHEMA_CHANGE",
    "TRUNCATE":        "SCHEMA_CHANGE",
    # DATA_CHANGE
    "INSERT":          "DATA_CHANGE",
    "UPDATE":          "DATA_CHANGE",
    "DELETE":          "DATA_CHANGE",
    "REPLACE":         "DATA_CHANGE",
    "LOAD_DATA":       "DATA_CHANGE",
    # PRIVILEGE_CHANGE
    "GRANT":           "PRIVILEGE_CHANGE",
    "REVOKE":          "PRIVILEGE_CHANGE",
    # AUTHENTICATION
    "CREATE_USER":     "AUTHENTICATION",
    "DROP_USER":       "AUTHENTICATION",
    "ALTER_USER":      "AUTHENTICATION",
    "SET_PASSWORD":    "AUTHENTICATION",
    # TRANSACTION
    "BEGIN":           "TRANSACTION",
    "COMMIT":          "TRANSACTION",
    "ROLLBACK":        "TRANSACTION",
    "XID":             "TRANSACTION",
    # CONFIGURATION
    "SET":             "CONFIGURATION",
    "INTVAR":          "CONFIGURATION",
    "USE":             "CONFIGURATION",
    # METADATA
    "BINLOG":          "METADATA",
    "START":           "METADATA",
    "STOP":            "METADATA",
    "ROTATE":          "METADATA",
    "FORMAT_DESCRIPTION": "METADATA",
    # UNKNOWN
    "UNKNOWN":         "UNKNOWN",
}


# ═══════════════════════════════════════════════════════════════════════════════
#  SQL → Event-type reclassifier
#  The parser emits "UNKNOWN" for BEGIN/COMMIT/ROLLBACK — we fix that here.
# ═══════════════════════════════════════════════════════════════════════════════

def _reclassify_unknown(event_type: str, sql: str) -> str:
    """
    If the parser left an event as UNKNOWN, try to derive a better type
    from the leading SQL keyword.
    """
    if event_type != "UNKNOWN" or not sql:
        return event_type
    # Strip trailing semicolons before first-word lookup
    cleaned = sql.strip().rstrip(";").strip()
    first = cleaned.upper().split()[0] if cleaned else ""
    REMAP = {
        "BEGIN":    "BEGIN",
        "COMMIT":   "COMMIT",
        "ROLLBACK": "ROLLBACK",
        "USE":      "USE",
        "SET":      "SET",
        "START":    "START",
        "STOP":     "STOP",
        "XA":       "XID",
    }
    return REMAP.get(first, "UNKNOWN")


# ═══════════════════════════════════════════════════════════════════════════════
#  PARSED-EVENT-FILE READER
#  Reads the key:value block format written by render_events().
# ═══════════════════════════════════════════════════════════════════════════════

_FIELD_RE = re.compile(r'^\s{2}([\w ]+?)\s*:\s*(.*)')


def _parse_block(lines: List[str]) -> Dict[str, str]:
    """
    Parse a single event block (lines between ==== markers).
    Returns a raw dict of string field → string value.
    """
    raw: Dict[str, str] = {}
    for line in lines:
        m = _FIELD_RE.match(line)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip()
            raw[key] = val
    return raw


def _read_parsed_events_file(filepath: str) -> List[Dict[str, str]]:
    """
    Split parsed_events.txt into individual event blocks and parse each one.
    Stops at the Summary section.
    Skips FILE: separator lines and other non-event blocks.
    """
    raw_events: List[Dict[str, str]] = []
    current_block: List[str] = []
    in_event   = False
    in_summary = False

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.rstrip("\r\n")

            # Detect summary boundary
            if re.match(r'[=]+\s*$', stripped) and not in_event:
                pass  # blank separator
            if stripped.strip().lower() == "summary":
                in_summary = True
                break

            if stripped.startswith("=" * 10):
                # Start of a new event block — flush the previous one
                if in_event and current_block:
                    raw_events.append(_parse_block(current_block))
                current_block = []
                in_event = True
                continue

            if stripped.startswith("-" * 10):
                # End of current event block
                if in_event and current_block:
                    raw_events.append(_parse_block(current_block))
                current_block = []
                in_event = False
                continue

            if in_event:
                current_block.append(stripped)

    # Flush trailing block if file didn't end cleanly
    if in_event and current_block:
        raw_events.append(_parse_block(current_block))

    return raw_events


# ═══════════════════════════════════════════════════════════════════════════════
#  TYPE COERCIONS
# ═══════════════════════════════════════════════════════════════════════════════

def _to_int_or_none(value: str) -> Optional[int]:
    if not value or not value.strip():
        return None
    try:
        return int(value.strip())
    except (ValueError, TypeError):
        return None


def _to_str_or_none(value: str) -> Optional[str]:
    if not value or not value.strip():
        return None
    return value.strip()


# ═══════════════════════════════════════════════════════════════════════════════
#  FIELD ALIASES
#  The parsed_events.txt uses human-friendly labels; map them to schema keys.
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
#  HEADER-TYPE → EVENT TYPE MAP
#  For events where the parser left event_type as UNKNOWN / empty but the
#  header_type (raw binlog event class) tells us what it is.
# ═══════════════════════════════════════════════════════════════════════════════

_HEADER_TYPE_MAP: Dict[str, str] = {
    "Xid":               "XID",
    "XID":               "XID",
    "Write_rows":        "INSERT",
    "Update_rows":       "UPDATE",
    "Delete_rows":       "DELETE",
    "Write_rows_v1":     "INSERT",
    "Update_rows_v1":    "UPDATE",
    "Delete_rows_v1":    "DELETE",
    "Table_map":         "METADATA",
    "Rotate":            "ROTATE",
    "Format_desc":       "FORMAT_DESCRIPTION",
    "Intvar":            "INTVAR",
    "Rand":              "CONFIGURATION",
    "User_var":          "CONFIGURATION",
    "Begin_load_query":  "LOAD_DATA",
    "Execute_load_query": "LOAD_DATA",
    "Append_block":      "LOAD_DATA",
    "Delete_file":       "METADATA",
    "Start":             "START",
    "Stop":              "STOP",
    "Previous_gtids":    "METADATA",
    "Gtid":              "METADATA",
    "Anonymous_Gtid":    "METADATA",
}

_FIELD_ALIASES = {
    "Event Type":  "event_type",
    "Log Pos":     "log_position",
    "End Log Pos": "end_log_position",
    "Timestamp":   "timestamp",
    "Server ID":   "server_id",
    "Thread ID":   "thread_id",
    "Exec Time":   "exec_time",
    "Error Code":  "error_code",
    "XID":         "xid",
    "Header Type": "header_type",
    "Database":    "database",
    "Table":       "table",
    "User":        "user",
    "SQL":         "sql",
}

# Regex that matches the ==...FILE: mysql-bin.NNNNNN...== banner emitted by
# mysqlbinlog when stitching multiple binlog files into one stream.
# It may appear (a) as the entire SQL field, or (b) appended to real SQL
# (e.g. "COMMIT; ====FILE: mysql-bin.000018====").
_FILE_BANNER_RE = re.compile(
    r'=+\s*FILE:\s*[\w./-]+\s*=+',
    re.IGNORECASE,
)


def _strip_structural_noise(sql: str) -> Optional[str]:
    """
    Remove embedded FILE: banners from a SQL string.

    Returns:
        * None  — if the SQL contained nothing but a banner (skip the event).
        * str   — the cleaned SQL with the banner stripped out.
    """
    cleaned = _FILE_BANNER_RE.sub('', sql).strip().rstrip(';').strip()
    return cleaned if cleaned else None


# ═══════════════════════════════════════════════════════════════════════════════
#  NORMALIZER
# ═══════════════════════════════════════════════════════════════════════════════

class DatabaseNormalizer:
    """
    Converts parsed_events.txt blocks into a fully-typed, tool-agnostic
    list of event dicts.

    Output schema (per event):
        event_id          int      Sequential ID, 1-based
        event_type        str      Normalised type (CREATE_DATABASE, INSERT …)
        category          str      High-level category (SCHEMA_CHANGE, DATA_CHANGE …)
        timestamp         int|null Unix epoch from SET TIMESTAMP
        server_id         int|null
        thread_id         int|null
        exec_time         int|null
        database          str|null Active schema context
        table             str|null Table name (if applicable)
        user              str|null user@host (if applicable)
        sql               str|null Original SQL statement
        log_position      int|null Start position in binlog
        end_log_position  int|null End position in binlog
        xid               int|null Transaction ID
        error_code        int|null 0 = success
        success           bool     True when error_code == 0 or error_code is null
        header_type       str|null Raw event type from binlog header
    """

    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def normalize_file(self, input_path: str) -> List[Dict[str, Any]]:
        """Read parsed_events.txt and return a list of normalised event dicts."""
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Parsed events file not found: {input_path}")

        raw_blocks = _read_parsed_events_file(input_path)
        events: List[Dict[str, Any]] = []
        event_id = 0

        for block in raw_blocks:
            try:
                ev = self._normalize_block(block)
                if ev is None:
                    continue   # skip pseudo-events (FILE: separators)
                event_id += 1
                ev["event_id"] = event_id
                events.append(ev)
            except Exception as exc:
                self.errors.append(f"Block {event_id + 1}: {type(exc).__name__}: {exc}")
                # Never stop on a single bad event

        return events

    def save(self, output_path: str, events: List[Dict[str, Any]]) -> None:
        """Write the normalised event list to a JSON file."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, ensure_ascii=False)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _normalize_block(self, raw: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """
        Convert one raw string-dict block into a fully-typed event dict.
        Returns None for pseudo-events that should be skipped.
        """
        # Remap field aliases
        mapped: Dict[str, str] = {}
        for label, value in raw.items():
            schema_key = _FIELD_ALIASES.get(label)
            if schema_key:
                mapped[schema_key] = value

        sql_raw     = _to_str_or_none(mapped.get("sql", ""))
        header_type = _to_str_or_none(mapped.get("header_type", ""))

        # ── Structural noise removal ─────────────────────────────────────────
        # Strip embedded FILE: banners (===FILE: mysql-bin.NNNNN===) that
        # mysqlbinlog injects between files. The banner may be the entire SQL
        # field (pure separator event → drop) or appended after real SQL
        # (e.g. "COMMIT; ====FILE:...====" → keep just "COMMIT").
        if sql_raw:
            sql_raw = _strip_structural_noise(sql_raw)
            # If nothing is left the whole event was just a banner → skip.
            if sql_raw is None:
                return None

        # ── Drop structurally-empty blocks ────────────────────────────────────
        # Events with neither SQL nor a known header_type are row-format binlog
        # artifacts (Write_rows / Update_rows / Delete_rows) that the parser
        # could not decode into readable SQL. Silently discard them — they carry
        # no actionable information and must NOT appear as UNKNOWN.
        if not sql_raw and not header_type:
            return None

        # ── STOP blocks with no SQL ───────────────────────────────────────────
        # The parser emits a STOP-typed event for the structural end-of-binlog
        # marker. When it has no SQL text (pure structural event) silently drop
        # it. We already record STOP events that carry real position metadata.
        event_type_raw = _to_str_or_none(mapped.get("event_type", "")) or "UNKNOWN"
        if event_type_raw == "STOP" and header_type == "Stop" and not sql_raw:
            return None

        # Resolve event_type — apply UNKNOWN reclassification from SQL
        event_type = _reclassify_unknown(event_type_raw, sql_raw or "")

        # If still UNKNOWN but header_type gives us a hint, use that
        if event_type == "UNKNOWN" and header_type:
            event_type = _HEADER_TYPE_MAP.get(header_type, "UNKNOWN")

        # Category
        category = CATEGORY_MAP.get(event_type, "UNKNOWN")

        # Numeric fields
        timestamp        = _to_int_or_none(mapped.get("timestamp", ""))
        server_id        = _to_int_or_none(mapped.get("server_id", ""))
        thread_id        = _to_int_or_none(mapped.get("thread_id", ""))
        exec_time        = _to_int_or_none(mapped.get("exec_time", ""))
        log_position     = _to_int_or_none(mapped.get("log_position", ""))
        end_log_position = _to_int_or_none(mapped.get("end_log_position", ""))
        xid              = _to_int_or_none(mapped.get("xid", ""))
        error_code       = _to_int_or_none(mapped.get("error_code", ""))

        # STOP pseudo-events have meaningful binlog position but no SQL text;
        # give them a synthetic SQL so downstream isn't confused.
        if event_type == "STOP" and not sql_raw:
            sql_raw = "STOP"

        # success: True when error_code is 0 or absent
        success = (error_code is None) or (error_code == 0)

        # String / nullable fields
        database = _to_str_or_none(mapped.get("database", ""))
        table    = _to_str_or_none(mapped.get("table", ""))
        user     = _to_str_or_none(mapped.get("user", ""))

        return {
            "event_id":         None,          # filled by caller
            "event_type":       event_type,
            "category":         category,
            "timestamp":        timestamp,
            "server_id":        server_id,
            "thread_id":        thread_id,
            "exec_time":        exec_time,
            "database":         database,
            "table":            table,
            "user":             user,
            "sql":              sql_raw,
            "log_position":     log_position,
            "end_log_position": end_log_position,
            "xid":              xid,
            "error_code":       error_code,
            "success":          success,
            "header_type":      header_type,
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  SUMMARY BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

def build_normalization_summary(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a summary dict covering event types, categories, and null-field counts.
    """
    from collections import Counter

    type_counts     = Counter(e["event_type"] for e in events)
    category_counts = Counter(e["category"]   for e in events)

    missing_db    = sum(1 for e in events if e["database"]  is None)
    missing_table = sum(1 for e in events if e["table"]     is None)
    missing_user  = sum(1 for e in events if e["user"]      is None)
    missing_ts    = sum(1 for e in events if e["timestamp"] is None)

    return {
        "total_events":    len(events),
        "event_types":     dict(sorted(type_counts.items())),
        "categories":      dict(sorted(category_counts.items())),
        "missing_fields": {
            "database":  missing_db,
            "table":     missing_table,
            "user":      missing_user,
            "timestamp": missing_ts,
        },
    }


def print_summary(summary: Dict[str, Any], errors: List[str]) -> None:
    """Print a human-readable normalization summary."""
    W = 40
    print()
    print("=" * W)
    print("  Normalization Summary")
    print("=" * W)
    print(f"\n  Total Events: {summary['total_events']}\n")

    print("  Events by Type:")
    for et, cnt in sorted(summary["event_types"].items()):
        print(f"    {et:<30} : {cnt}")

    print("\n  Events by Category:")
    for cat, cnt in sorted(summary["categories"].items()):
        print(f"    {cat:<22} : {cnt}")

    print("\n  Missing Fields (null values):")
    for field, cnt in summary["missing_fields"].items():
        print(f"    {field:<22} : {cnt}")

    print(f"\n  Normalization Errors: {len(errors)}")
    if errors:
        for err in errors:
            print(f"    [ERROR] {err}")

    print("=" * W)
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse

    SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
    DATABASE_DIR = os.path.dirname(SCRIPT_DIR)

    parser = argparse.ArgumentParser(description="Normalize mysqlbinlog parsed events to JSON schema")
    parser.add_argument(
        "--input", "-i",
        default=os.path.join(DATABASE_DIR, "raw", "mysqlbinlog_parsed_events.txt"),
        help="Path to parsed_events.txt (default: database/raw/mysqlbinlog_parsed_events.txt)",
    )
    parser.add_argument(
        "--output", "-o",
        default=os.path.join(DATABASE_DIR, "normalized", "mysqlbinlog_normalized_events.json"),
        help="Path for output JSON (default: database/normalized/mysqlbinlog_normalized_events.json)",
    )
    args = parser.parse_args()

    print(f"[INFO] Input  : {args.input}")
    print(f"[INFO] Output : {args.output}")
    print()

    norm   = DatabaseNormalizer()
    events = norm.normalize_file(args.input)

    norm.save(args.output, events)
    print(f"[INFO] Written : {args.output}  ({len(events)} events)")

    summary = build_normalization_summary(events)
    print_summary(summary, norm.errors)


if __name__ == "__main__":
    main()
