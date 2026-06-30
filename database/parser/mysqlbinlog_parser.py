"""
mysqlbinlog_parser.py
=====================
Parses the text output produced by:

    mysqlbinlog mysql-bin.*  > all_binlogs.txt

and extracts every binlog event into a structured dictionary.

Supported event types (auto-detected from SQL):
    CREATE_DATABASE, DROP_DATABASE
    CREATE_USER,     DROP_USER
    GRANT,           REVOKE
    INSERT,          UPDATE,  DELETE
    CREATE_TABLE,    ALTER_TABLE, DROP_TABLE, TRUNCATE
    USE,             SET
    START,           STOP
    BINLOG           (raw base64 blocks)
    UNKNOWN

Each event dict contains:
    log_pos     - starting position in binlog  (str)
    end_log_pos - end position                 (str)
    timestamp   - unix timestamp from SET TIMESTAMP (str)
    server_id   - server id from header        (str)
    thread_id   - thread_id from header        (str)
    exec_time   - exec_time from header        (str)
    error_code  - error_code from header       (str)
    xid         - xid from header              (str)
    header_type - raw event type in header     (str)  e.g. "Query", "Stop", "Start"
    event_type  - normalised event type        (str)  e.g. "CREATE_DATABASE"
    database    - schema context               (str)
    table       - table name (if applicable)   (str)
    user        - user (if applicable)         (str)
    sql         - the meaningful SQL statement (str)
"""

import re
from typing import List, Dict, Any

# ─── Regex Patterns ────────────────────────────────────────────────────────────

# Matches:  # at 107
_AT_RE = re.compile(r'^#\s+at\s+(\d+)\s*$')

# Matches:  #160315 10:06:04 server id 1  end_log_pos 202    Query  thread_id=8 ...
_HEADER_RE = re.compile(
    r'^#(\d{6})\s+(\d{1,2}:\d{2}:\d{2})\s+'   # date + time
    r'server\s+id\s+(\d+)\s+'                   # server id
    r'end_log_pos\s+(\d+)\s+'                   # end_log_pos
    r'([\w: ]+?)'                                # event type (Stop, Start, Query …)
    r'(?:\s+thread_id=(\d+))?'                  # optional thread_id
    r'(?:\s+exec_time=(\d+))?'                  # optional exec_time
    r'(?:\s+error_code=(\d+))?'                 # optional error_code
    r'(?:\s+xid=(\d+))?'                        # optional xid
    r'\s*$'
)

# SET TIMESTAMP=1458050764  or  SET TIMESTAMP=1458050764/*!*/;
_TIMESTAMP_RE = re.compile(r'^SET\s+TIMESTAMP\s*=\s*(\d+)', re.IGNORECASE)

# use `wordpress`/*!*/;
_USE_RE = re.compile(r'^use\s+`?([^`\s;/*]+)`?', re.IGNORECASE)

# Lines to always skip (session / infrastructure noise)
_SKIP_PREFIXES = (
    '/*!',          # conditional comments
    'DELIMITER',
    'ROLLBACK',
    '# End of',
    '# at ',        # handled separately
    '#',            # header comment lines (handled separately)
    "SET @@session.",
    "SET @@SESSION.",
    "/*\\C",
)

# Noise SQL that isn't an actual business event
_NOISE_SQL_PREFIXES = (
    'SET @@session.',
    'SET @@SESSION.',
    'SET @@pseudo',
    '/*\\C',
)


# ─── SQL Event Type Classification ────────────────────────────────────────────

def classify_sql(sql: str) -> Dict[str, str]:
    """
    Given a SQL statement, return a dict with:
        event_type, database, table, user
    """
    sql_upper = sql.strip().upper()
    result = {"event_type": "UNKNOWN", "database": "", "table": "", "user": ""}

    if not sql_upper:
        return result

    if sql_upper.startswith("CREATE DATABASE") or sql_upper.startswith("CREATE SCHEMA"):
        result["event_type"] = "CREATE_DATABASE"
        m = re.search(r'(?:DATABASE|SCHEMA)\s+(?:IF\s+NOT\s+EXISTS\s+)?`?(\w+)`?', sql, re.IGNORECASE)
        if m:
            result["database"] = m.group(1)

    elif sql_upper.startswith("DROP DATABASE") or sql_upper.startswith("DROP SCHEMA"):
        result["event_type"] = "DROP_DATABASE"
        m = re.search(r'(?:DATABASE|SCHEMA)\s+(?:IF\s+EXISTS\s+)?`?(\w+)`?', sql, re.IGNORECASE)
        if m:
            result["database"] = m.group(1)

    elif sql_upper.startswith("CREATE USER"):
        result["event_type"] = "CREATE_USER"
        m = re.search(r"'([^']+)'@'([^']+)'", sql)
        if m:
            result["user"] = f"{m.group(1)}@{m.group(2)}"

    elif sql_upper.startswith("DROP USER"):
        result["event_type"] = "DROP_USER"
        m = re.search(r"'([^']+)'@'([^']+)'", sql)
        if m:
            result["user"] = f"{m.group(1)}@{m.group(2)}"

    elif sql_upper.startswith("GRANT"):
        result["event_type"] = "GRANT"
        m = re.search(r"ON\s+`?([^`\s.]+)`?\.(?:`?([^`\s.]+)`?)", sql, re.IGNORECASE)
        if m:
            if m.group(1) != "*":
                result["database"] = m.group(1)
            if m.group(2) != "*":
                result["table"] = m.group(2)
        m2 = re.search(r"TO\s+'([^']+)'@'([^']+)'", sql, re.IGNORECASE)
        if m2:
            result["user"] = f"{m2.group(1)}@{m2.group(2)}"

    elif sql_upper.startswith("REVOKE"):
        result["event_type"] = "REVOKE"
        m = re.search(r"FROM\s+'([^']+)'@'([^']+)'", sql, re.IGNORECASE)
        if m:
            result["user"] = f"{m.group(1)}@{m.group(2)}"

    elif sql_upper.startswith("INSERT"):
        result["event_type"] = "INSERT"
        m = re.search(r'INSERT\s+(?:INTO\s+)?`?([^`\s(]+)`?(?:\.`?([^`\s(]+)`?)?', sql, re.IGNORECASE)
        if m:
            if m.group(2):
                result["database"] = m.group(1)
                result["table"] = m.group(2)
            else:
                result["table"] = m.group(1)

    elif sql_upper.startswith("UPDATE"):
        result["event_type"] = "UPDATE"
        m = re.search(r'UPDATE\s+`?([^`\s]+)`?(?:\.`?([^`\s]+)`?)?', sql, re.IGNORECASE)
        if m:
            if m.group(2):
                result["database"] = m.group(1)
                result["table"] = m.group(2)
            else:
                result["table"] = m.group(1)

    elif sql_upper.startswith("DELETE"):
        result["event_type"] = "DELETE"
        m = re.search(r'DELETE\s+FROM\s+`?([^`\s]+)`?(?:\.`?([^`\s]+)`?)?', sql, re.IGNORECASE)
        if m:
            if m.group(2):
                result["database"] = m.group(1)
                result["table"] = m.group(2)
            else:
                result["table"] = m.group(1)

    elif sql_upper.startswith("ALTER TABLE"):
        result["event_type"] = "ALTER_TABLE"
        m = re.search(r'ALTER\s+TABLE\s+`?([^`\s]+)`?(?:\.`?([^`\s]+)`?)?', sql, re.IGNORECASE)
        if m:
            if m.group(2):
                result["database"] = m.group(1)
                result["table"] = m.group(2)
            else:
                result["table"] = m.group(1)

    elif sql_upper.startswith("CREATE TABLE"):
        result["event_type"] = "CREATE_TABLE"
        m = re.search(r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([^`\s(]+)`?(?:\.`?([^`\s(]+)`?)?', sql, re.IGNORECASE)
        if m:
            if m.group(2):
                result["database"] = m.group(1)
                result["table"] = m.group(2)
            else:
                result["table"] = m.group(1)

    elif sql_upper.startswith("DROP TABLE"):
        result["event_type"] = "DROP_TABLE"
        m = re.search(r'DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?`?([^`\s(]+)`?(?:\.`?([^`\s(]+)`?)?', sql, re.IGNORECASE)
        if m:
            if m.group(2):
                result["database"] = m.group(1)
                result["table"] = m.group(2)
            else:
                result["table"] = m.group(1)

    elif sql_upper.startswith("TRUNCATE"):
        result["event_type"] = "TRUNCATE"
        m = re.search(r'TRUNCATE\s+(?:TABLE\s+)?`?([^`\s(]+)`?(?:\.`?([^`\s(]+)`?)?', sql, re.IGNORECASE)
        if m:
            if m.group(2):
                result["database"] = m.group(1)
                result["table"] = m.group(2)
            else:
                result["table"] = m.group(1)

    elif sql_upper.startswith("USE"):
        result["event_type"] = "USE"
        m = re.search(r'USE\s+`?(\w+)`?', sql, re.IGNORECASE)
        if m:
            result["database"] = m.group(1)

    elif sql_upper.startswith("SET"):
        result["event_type"] = "SET"

    elif sql_upper.startswith("START"):
        result["event_type"] = "START"

    elif sql_upper.startswith("STOP"):
        result["event_type"] = "STOP"

    return result


# ─── Main Parser ───────────────────────────────────────────────────────────────

class MysqlBinlogParser:
    """
    Stateful parser for mysqlbinlog text output.

    Usage:
        parser = MysqlBinlogParser()
        events = parser.parse_file("all_binlogs.txt")
        for ev in events:
            print(ev)
    """

    def __init__(self):
        self._reset()

    def _reset(self):
        self._events: List[Dict[str, Any]] = []
        self._current_log_pos: str = ""
        self._current_header: Dict[str, str] = {}
        self._current_timestamp: str = ""
        self._current_db: str = ""
        self._sql_lines: List[str] = []
        self._in_binlog_block: bool = False
        self._binlog_lines: List[str] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def parse_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Parse a mysqlbinlog output file and return a list of event dicts."""
        self._reset()
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError as exc:
            raise RuntimeError(f"Cannot open binlog file: {filepath}") from exc

        for line in lines:
            self._process_line(line.rstrip("\r\n"))

        # Flush any pending event
        self._flush_event()
        return self._events

    # ── Line Dispatcher ────────────────────────────────────────────────────────

    def _process_line(self, line: str) -> None:
        stripped = line.strip()

        # ── BINLOG base64 block handling ──────────────────────────────────────
        if stripped == "BINLOG '":
            self._in_binlog_block = True
            self._binlog_lines = []
            return

        if self._in_binlog_block:
            if stripped == "'/*!*/;":
                # End of BINLOG block — emit as a BINLOG event
                self._flush_event()
                ev = self._new_event()
                ev["event_type"]  = "BINLOG"
                ev["header_type"] = "BINLOG"
                ev["sql"]         = "BINLOG '" + " ".join(self._binlog_lines) + "'"
                ev["log_pos"]     = self._current_log_pos
                self._current_log_pos = ""
                self._events.append(ev)
                self._in_binlog_block = False
                self._binlog_lines    = []
            else:
                self._binlog_lines.append(stripped)
            return

        # ── # at <pos> ────────────────────────────────────────────────────────
        m_at = _AT_RE.match(stripped)
        if m_at:
            # Flush previous event before starting a new block
            self._flush_event()
            self._current_log_pos = m_at.group(1)
            self._sql_lines       = []
            self._current_header  = {}
            return

        # ── Event header line  (#160315 10:06:04 server id ...) ──────────────
        if stripped.startswith("#") and not stripped.startswith("# "):
            self._try_parse_header(stripped)
            return

        # ── Skip pure noise lines ─────────────────────────────────────────────
        if any(stripped.startswith(p) for p in _SKIP_PREFIXES):
            return

        # ── SET TIMESTAMP — capture for event metadata ────────────────────────
        m_ts = _TIMESTAMP_RE.match(stripped)
        if m_ts:
            self._current_timestamp = m_ts.group(1)
            return

        # ── use `db` — capture context database ──────────────────────────────
        m_use = _USE_RE.match(stripped)
        if m_use and stripped.endswith("/*!*/;"):
            self._current_db = m_use.group(1)
            return

        # ── Terminal marker /*!*/; on its own means end of a SQL statement ────
        if stripped == "/*!*/;":
            return

        # ── Collect SQL lines ─────────────────────────────────────────────────
        # Skip session-noise SQL (these are header SET lines, not business SQL)
        if any(stripped.startswith(p) for p in _NOISE_SQL_PREFIXES):
            return

        # Only accumulate non-empty, non-comment, non-delimiter lines
        if stripped and not stripped.startswith("--"):
            self._sql_lines.append(stripped)

    # ── Header Parsing ─────────────────────────────────────────────────────────

    def _try_parse_header(self, line: str) -> None:
        """Try to parse a binlog event header comment line."""
        m = _HEADER_RE.match(line)
        if not m:
            return
        # Groups: date, time, server_id, end_log_pos, event_type,
        #         thread_id, exec_time, error_code, xid
        self._current_header = {
            "date":       m.group(1),
            "time":       m.group(2),
            "server_id":  m.group(3),
            "end_log_pos": m.group(4),
            "header_type": m.group(5).strip(),
            "thread_id":  m.group(6) or "",
            "exec_time":  m.group(7) or "",
            "error_code": m.group(8) or "",
            "xid":        m.group(9) or "",
        }

    # ── Event Flush ────────────────────────────────────────────────────────────

    def _flush_event(self) -> None:
        """
        Assemble and store the current pending event from accumulated state,
        but only if there is meaningful SQL to store.
        """
        if not self._sql_lines:
            # Nothing meaningful to emit
            self._sql_lines = []
            return

        sql = self._clean_sql(" ".join(self._sql_lines))
        if not sql:
            self._sql_lines = []
            return

        ev = self._new_event()
        ev["sql"] = sql

        # Classify
        classified = classify_sql(sql)
        ev["event_type"] = classified["event_type"]
        ev["table"]      = classified["table"]
        ev["user"]       = classified["user"]

        # Database: prefer USE context, then classified db
        ev["database"] = classified["database"] or self._current_db

        # Handle STOP events from header even without SQL
        if ev["header_type"] == "Stop" and ev["event_type"] == "UNKNOWN":
            ev["event_type"] = "STOP"

        self._events.append(ev)
        self._sql_lines = []

    def _new_event(self) -> Dict[str, Any]:
        """Build an event dict pre-populated with current context."""
        h = self._current_header
        return {
            "log_pos":      self._current_log_pos,
            "end_log_pos":  h.get("end_log_pos", ""),
            "timestamp":    self._current_timestamp,
            "server_id":    h.get("server_id", ""),
            "thread_id":    h.get("thread_id", ""),
            "exec_time":    h.get("exec_time", ""),
            "error_code":   h.get("error_code", ""),
            "xid":          h.get("xid", ""),
            "header_type":  h.get("header_type", ""),
            "event_type":   "UNKNOWN",
            "database":     self._current_db,
            "table":        "",
            "user":         "",
            "sql":          "",
        }

    @staticmethod
    def _clean_sql(raw: str) -> str:
        """Strip mysqlbinlog noise tokens from a SQL string."""
        # Remove  /*!*/;  and  /*!  ... */  markers
        cleaned = re.sub(r'/\*!(?:\d+)?.*?\*/', '', raw)
        # Remove  /*!*/;
        cleaned = re.sub(r'/\*!\*/;?', '', cleaned)
        # Collapse whitespace
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        # Remove trailing semicolons and markers
        cleaned = cleaned.rstrip(';').strip()
        return cleaned


# ─── Summary ───────────────────────────────────────────────────────────────────

def build_summary(events: List[Dict[str, Any]]) -> Dict[str, int]:
    """Return a frequency count dict of event_type."""
    counts: Dict[str, int] = {}
    for ev in events:
        et = ev.get("event_type", "UNKNOWN")
        counts[et] = counts.get(et, 0) + 1
    return counts


# ─── Text Renderer ─────────────────────────────────────────────────────────────

def render_events(events: List[Dict[str, Any]], output_path: str) -> None:
    """Write all events and a summary block to output_path."""
    import os
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    ORDERED_TYPES = [
        "CREATE_DATABASE", "DROP_DATABASE",
        "CREATE_USER",     "DROP_USER",
        "GRANT",           "REVOKE",
        "INSERT",          "UPDATE",  "DELETE",
        "ALTER_TABLE",     "CREATE_TABLE", "DROP_TABLE", "TRUNCATE",
        "USE",             "SET",
        "START",           "STOP",
        "BINLOG",          "UNKNOWN",
    ]

    summary = build_summary(events)

    with open(output_path, "w", encoding="utf-8") as f:

        # ── Events ────────────────────────────────────────────────────────────
        for idx, ev in enumerate(events, 1):
            f.write("=" * 52 + "\n")
            f.write(f"Event #{idx}\n")
            f.write("=" * 52 + "\n\n")

            f.write(f"  Event Type  : {ev['event_type']}\n")
            f.write(f"  Log Pos     : {ev['log_pos']}\n")
            f.write(f"  End Log Pos : {ev['end_log_pos']}\n")
            f.write(f"  Timestamp   : {ev['timestamp']}\n")
            f.write(f"  Server ID   : {ev['server_id']}\n")
            f.write(f"  Thread ID   : {ev['thread_id']}\n")
            f.write(f"  Exec Time   : {ev['exec_time']}\n")
            f.write(f"  Error Code  : {ev['error_code']}\n")
            f.write(f"  XID         : {ev['xid']}\n")
            f.write(f"  Header Type : {ev['header_type']}\n")
            f.write(f"  Database    : {ev['database']}\n")
            f.write(f"  Table       : {ev['table']}\n")
            f.write(f"  User        : {ev['user']}\n")
            f.write(f"  SQL         : {ev['sql']}\n")
            f.write("\n" + "-" * 52 + "\n\n")

        # ── Summary ───────────────────────────────────────────────────────────
        f.write("\n" + "=" * 52 + "\n")
        f.write("Summary\n")
        f.write("=" * 52 + "\n\n")
        f.write(f"  Total Events : {len(events)}\n\n")

        for et in ORDERED_TYPES:
            count = summary.get(et, 0)
            label = et.replace("_", " ").title()
            # Align label
            f.write(f"  {label:<22}: {count}\n")

        # Print any event types not in the ordered list
        extras = {k: v for k, v in summary.items() if k not in ORDERED_TYPES}
        for et, count in sorted(extras.items()):
            f.write(f"  {et:<22}: {count}\n")

        f.write("\n")
