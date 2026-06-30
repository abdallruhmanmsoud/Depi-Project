"""
Shared utilities for all Memory Normalizers.
Provides line filtering, safe parsing, and common helpers
for handling raw Volatility 3 text output.
"""

import re


# ─── Compiled Patterns ──────────────────────────────────────────────────────

_SEPARATOR_RE = re.compile(r'^[\s─━┄┈─\-=│┃|+┌┐└┘├┤┬┴┼]+$')

_SKIP_PREFIXES = (
    "#",
    "Volatility",
    "[STDERR]",
    "Progress:",
)

_HEX_DUMP_RE = re.compile(
    r'^[0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2}){7,}'
)

_DISASM_RE = re.compile(
    r'^0x[0-9a-fA-F]+:\s+'
)


def is_valid_data_line(line: str) -> bool:
    """
    Returns True only if the line is a real data row
    from Volatility output. Filters out:
      - Empty / whitespace-only lines
      - Comment lines starting with #
      - Volatility banner lines
      - [STDERR] sections
      - Progress: lines
      - Separator lines (dashes, unicode box chars)
      - Hex dump lines (malfind raw bytes)
      - Disassembly lines (malfind disasm)
    """
    stripped = line.strip()

    if not stripped:
        return False

    for prefix in _SKIP_PREFIXES:
        if stripped.startswith(prefix):
            return False

    if _SEPARATOR_RE.match(stripped):
        return False

    return True


def is_header_line(line: str, expected_start: str) -> bool:
    """
    Returns True if the line is the column header row.
    Matches by checking if the stripped line starts with expected_start.
    """
    return line.strip().startswith(expected_start)


def safe_int(value: str, default: int = 0) -> int:
    """Safely parse a string to int, returning default on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_str(value: str) -> str:
    """Clean a string value, return empty string for N/A or dash."""
    if value in ("N/A", "-", ""):
        return ""
    return value.strip()


def safe_bool(value: str) -> bool:
    """Parse a string to boolean."""
    return value.strip().lower() in ("true", "1", "yes")


def read_lines(filepath: str) -> list:
    """Read all lines from a file with UTF-8 encoding, ignoring errors."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()
