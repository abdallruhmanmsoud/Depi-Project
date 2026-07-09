"""
history_parser.py
──────────────────
Parses raw terminal output from BrowserHistoryView and Hindsight tools.
Both tools produce IDENTICAL output format (same SQLite queries on same tables),
so one parser handles both.

Output format from the tools:
    Step 2: ('url', 'title', visit_count)   <- urls table
    Step 3: ('target_path', 'tab_url')      <- downloads table

Usage:
    from parsing.history_parser import parse_history_output
    data = parse_history_output(raw_text)
"""

from __future__ import annotations
import re
from typing import Any


def parse_history_output(raw_text: str) -> dict[str, Any]:
    """
    Parse BrowserHistoryView / Hindsight raw terminal output.

    Returns
    -------
    dict with keys:
        urls: [{url, title, visit_count}]
        downloads: [{target_path, tab_url}]
        url_count: int
        download_count: int
    """
    data: dict[str, Any] = {
        "urls": [],
        "downloads": [],
        "url_count": 0,
        "download_count": 0,
    }

    # ── Parse URLs section (Step 2) ──
    # Format: ('https://example.com', 'Page Title', 15)
    urls_section = _extract_section(raw_text, "Extracting browsing", "Extracting downloads")
    for line in urls_section.splitlines():
        line = line.strip()
        m = re.match(r"\('(.+?)',\s*'(.*?)',\s*(\d+)\)$", line)
        if m:
            data["urls"].append({
                "url": m.group(1),
                "title": m.group(2),
                "visit_count": int(m.group(3)),
            })

    # ── Parse Downloads section (Step 3) ──
    # Format: ('/Downloads/file.exe', 'http://source.com/file.exe')
    downloads_section = _extract_section(raw_text, "Extracting downloads", None)
    for line in downloads_section.splitlines():
        line = line.strip()
        m = re.match(r"\('(.+?)',\s*'(.+?)'\)$", line)
        if m:
            data["downloads"].append({
                "target_path": m.group(1),
                "tab_url": m.group(2),
            })

    data["url_count"] = len(data["urls"])
    data["download_count"] = len(data["downloads"])

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
[Step 2/3] Extracting browsing history ...
('https://facebook.com/feed', 'Facebook', 60)
('https://google.com/search?q=python+tutorial', 'Google Search', 45)
('http://185.220.101.50:8080/gate.php?data=dXNlcjpwYXNz', 'C2 Panel', 15)
('http://paypal-secure-login.tk/verify?user=victim&token=abc123xyz', 'PayPal Security', 12)
('http://bit.ly/3xEvIlL1nk', 'Short Link', 2)
[Step 3/3] Extracting downloads history ...
('/Downloads/invoice_2024.exe', 'http://evil-invoice.tk/invoice_2024.exe')
('/Downloads/python_tutorial.pdf', 'https://realpython.com/python_tutorial.pdf')
('/Downloads/malware_payload.bin', 'http://185.220.101.50:8080/payload.bin')
BrowserHistoryView analysis complete.
"""
    result = parse_history_output(sample)
    print(json.dumps(result, indent=2))
