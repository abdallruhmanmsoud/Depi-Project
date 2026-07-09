"""
bft_parser.py
──────────────
Parses raw terminal output from the Browser Forensic ToolKit (BFT) tool.

BFT output format:
    Step 2: table names (urls, downloads, cookies, logins, entries)
    Step 3: ('url', 'title')                         <- urls table
    Step 4: ('host_key', 'name', 'value')            <- cookies table (WITH values)

BFT is unique vs BrowserHistoryView in two ways:
  1. It lists ALL table names (useful for schema detection)
  2. It extracts cookie VALUES (not just names) — richer data for anomaly detection

Usage:
    from parsing.bft_parser import parse_bft_output
    data = parse_bft_output(raw_text)
"""

from __future__ import annotations
import re
from typing import Any


def parse_bft_output(raw_text: str) -> dict[str, Any]:
    """
    Parse BFT raw terminal output into structured data.

    Returns
    -------
    dict with keys:
        db_type: str                    <- from 'file' command output
        tables: [str]                   <- all table names found in DB
        urls: [{url, title}]
        cookies: [{host_key, name, value}]
        url_count: int
        cookie_count: int
    """
    data: dict[str, Any] = {
        "db_type": "",
        "tables": [],
        "urls": [],
        "cookies": [],
        "url_count": 0,
        "cookie_count": 0,
    }

    # ── Parse DB type (Step 1) ──
    m = re.search(r":\s*(SQLite[^\n]+)", raw_text)
    if m:
        data["db_type"] = m.group(1).strip()

    # ── Parse table names (Step 2) ──
    tables_section = _extract_section(raw_text, "Extracting all tables", "Extracting history")
    for line in tables_section.splitlines():
        line = line.strip()
        if line and re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", line):
            data["tables"].append(line)

    # ── Parse URLs (Step 3) ──
    # Format: ('url', 'title')  — no visit_count in BFT
    urls_section = _extract_section(raw_text, "Extracting history", "Extracting cookies")
    for line in urls_section.splitlines():
        line = line.strip()
        m = re.match(r"\('(.+?)',\s*'(.*?)'\)$", line)
        if m:
            data["urls"].append({
                "url": m.group(1),
                "title": m.group(2),
            })

    # ── Parse Cookies (Step 4) ──
    # Format: ('host_key', 'name', 'value')
    cookies_section = _extract_section(raw_text, "Extracting cookies", None)
    for line in cookies_section.splitlines():
        line = line.strip()
        m = re.match(r"\('(.+?)',\s*'(.+?)',\s*'(.*?)'\)$", line)
        if m:
            data["cookies"].append({
                "host_key": m.group(1),
                "name": m.group(2),
                "value": m.group(3),
            })

    data["url_count"] = len(data["urls"])
    data["cookie_count"] = len(data["cookies"])

    return data


def _extract_section(text: str, start_marker: str, end_marker: str | None) -> str:
    start_match = re.search(re.escape(start_marker), text, re.IGNORECASE)
    if not start_match:
        return ""
    start_idx = start_match.end()
    if end_marker:
        end_match = re.search(re.escape(end_marker), text[start_idx:], re.IGNORECASE)
        if end_match:
            return text[start_idx: start_idx + end_match.start()]
    return text[start_idx:]


if __name__ == "__main__":
    import json
    sample = """
[Step 2/4] Extracting all tables ...
urls
downloads
cookies
logins
entries
[Step 3/4] Extracting history ...
('http://paypal-secure-login.tk/verify?user=victim&token=abc123xyz', 'PayPal Security')
('http://185.220.101.50:8080/gate.php?data=dXNlcjpwYXNz', 'C2 Panel')
('https://google.com/search?q=python+tutorial', 'Google Search')
[Step 4/4] Extracting cookies ...
('.paypal-secure-login.tk', 'session_id', 'abc123fakesession')
('.evil-tracker.xyz', 'tracking_id', 'victim_uid_98765')
('.185.220.101.50', 'gate_key', 'xK9mP2nL7qR4sT6v')
('.google.com', 'SIDCC', 'APoG2W8normal_val')
BFT analysis complete.
"""
    result = parse_bft_output(sample)
    print(json.dumps(result, indent=2))
