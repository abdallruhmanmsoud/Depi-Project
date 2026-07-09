"""
passview_parser.py
───────────────────
Parses raw terminal output from the WebBrowserPassView tool.

WebBrowserPassView output format:
    Step 1: ('origin_url', 'username_value')     <- logins table
    Step 2: ('host_key', 'name')                 <- cookies table (names only, no values)

Key difference from BFT:
  - Has LOGIN credentials (origin_url + username) — strongest phishing signal
  - Cookies WITHOUT values (privacy-safe subset)

The origin_url from logins is the most valuable data:
  a user saving a password to a phishing URL is a confirmed compromise indicator.

Usage:
    from parsing.passview_parser import parse_passview_output
    data = parse_passview_output(raw_text)
"""

from __future__ import annotations
import re
from typing import Any


def parse_passview_output(raw_text: str) -> dict[str, Any]:
    """
    Parse WebBrowserPassView raw terminal output into structured data.

    Returns
    -------
    dict with keys:
        logins: [{origin_url, username}]
        cookies: [{host_key, name}]
        login_count: int
        cookie_count: int
    """
    data: dict[str, Any] = {
        "logins": [],
        "cookies": [],
        "login_count": 0,
        "cookie_count": 0,
    }

    # ── Parse Logins (Step 1) ──
    # Format: ('http://paypal-secure-login.tk/login', 'victim@gmail.com')
    logins_section = _extract_section(raw_text, "Extracting saved passwords", "Checking for cookie")
    for line in logins_section.splitlines():
        line = line.strip()
        m = re.match(r"\('(.+?)',\s*'(.*?)'\)$", line)
        if m:
            data["logins"].append({
                "origin_url": m.group(1),
                "username": m.group(2),
            })

    # ── Parse Cookies (Step 2) ──
    # Format: ('.paypal-secure-login.tk', 'session_id')
    cookies_section = _extract_section(raw_text, "Checking for cookie", None)
    for line in cookies_section.splitlines():
        line = line.strip()
        m = re.match(r"\('(.+?)',\s*'(.+?)'\)$", line)
        if m:
            data["cookies"].append({
                "host_key": m.group(1),
                "name": m.group(2),
            })

    data["login_count"] = len(data["logins"])
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
[Step 1/2] Extracting saved passwords from browser DB ...
('http://paypal-secure-login.tk/login', 'victim@gmail.com')
('http://apple-id-verify.ml/signin', 'victim@icloud.com')
('https://google.com/accounts', 'user@gmail.com')
('http://185.220.101.50:8080/panel', 'admin')
('https://github.com/login', 'dev_user')
[Step 2/2] Checking for cookie data ...
('.paypal-secure-login.tk', 'session_id')
('.evil-tracker.xyz', 'tracking_id')
('.185.220.101.50', 'gate_key')
('.google.com', 'SIDCC')
WebBrowserPassView analysis complete.
"""
    result = parse_passview_output(sample)
    print(json.dumps(result, indent=2))
