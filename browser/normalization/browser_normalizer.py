"""
browser_normalizer.py
──────────────────────
Combines output from all browser forensic tools (BFT, BrowserHistoryView,
Hindsight, WebBrowserPassView) into a single normalized JSON ready for
the feature_extractor.py (URL-based phishing detection model).

Pipeline:
    Raw tool outputs
        ↓
    history_parser + bft_parser + passview_parser
        ↓
    browser_normalizer  ← YOU ARE HERE
        ↓
    feature_extractor.py (per-URL prediction)
        ↓
    model.pkl (phishing / benign)

Key design decisions:
  - All URLs from ALL sources are deduplicated into one list
  - Each URL carries metadata: source tool, visit_count, is_login_url, is_download_url
  - Downloads are tracked separately (tab_url = the actual URL to classify)
  - Cookies are tracked separately (host_key stripped of leading dot)
  - is_login_url = True means a saved password was found for this URL → HIGH RISK signal

Usage:
    from normalization.browser_normalizer import normalize_browser_case
    normalized = normalize_browser_case(
        history_raw="...",   # BrowserHistoryView or Hindsight output
        bft_raw="...",       # BFT output
        passview_raw="...",  # WebBrowserPassView output
        case_id="case_001",
        source_file="malicious_browser.db",
    )
"""

from __future__ import annotations
import os
import sys
import json
from datetime import datetime, timezone
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsing.history_parser import parse_history_output
from parsing.bft_parser import parse_bft_output
from parsing.passview_parser import parse_passview_output


def normalize_browser_case(
    history_raw: str,
    bft_raw: str,
    passview_raw: str,
    case_id: str,
    source_file: str,
) -> dict[str, Any]:
    """
    Build the normalized Browser JSON for one forensic case.

    Parameters
    ----------
    history_raw  : raw output from BrowserHistoryView OR Hindsight (same format)
    bft_raw      : raw output from BFT tool
    passview_raw : raw output from WebBrowserPassView tool
    case_id      : unique identifier (e.g. dashboard session id)
    source_file  : original .db filename

    Returns
    -------
    Normalized JSON dict with:
        urls        : deduplicated list of all URLs with metadata
        downloads   : all downloaded files with source URLs
        cookies     : all cookie hosts seen
        login_urls  : URLs where saved passwords were found (HIGH RISK)
        indicators  : flat numeric summary for ML pipeline
    """
    # ── Run all parsers ──────────────────────────────────────────────
    history_data  = parse_history_output(history_raw)
    bft_data      = parse_bft_output(bft_raw)
    passview_data = parse_passview_output(passview_raw)

    # ── Collect login URLs (strongest signal) ────────────────────────
    login_urls = {entry["origin_url"] for entry in passview_data["logins"]}

    # ── Deduplicate URLs from all sources ────────────────────────────
    url_map: dict[str, dict[str, Any]] = {}

    def _add_url(url: str, title: str, visit_count: int, source: str) -> None:
        if url not in url_map:
            url_map[url] = {
                "url": url,
                "title": title,
                "visit_count": visit_count,
                "sources": [source],
                "is_login_url": url in login_urls,
                "is_download_url": False,
            }
        else:
            url_map[url]["visit_count"] = max(
                url_map[url]["visit_count"], visit_count
            )
            if source not in url_map[url]["sources"]:
                url_map[url]["sources"].append(source)
            if url in login_urls:
                url_map[url]["is_login_url"] = True

    for entry in history_data["urls"]:
        _add_url(entry["url"], entry["title"], entry["visit_count"], "history")

    for entry in bft_data["urls"]:
        _add_url(entry["url"], entry["title"], 0, "bft")

    for entry in passview_data["logins"]:
        _add_url(entry["origin_url"], "", 0, "passview_login")

    # ── Downloads ────────────────────────────────────────────────────
    downloads = history_data["downloads"]
    for dl in downloads:
        tab_url = dl["tab_url"]
        if tab_url in url_map:
            url_map[tab_url]["is_download_url"] = True
        else:
            url_map[tab_url] = {
                "url": tab_url,
                "title": "",
                "visit_count": 0,
                "sources": ["download"],
                "is_login_url": tab_url in login_urls,
                "is_download_url": True,
            }

    # ── Cookies ──────────────────────────────────────────────────────
    cookie_map: dict[str, dict[str, Any]] = {}

    for c in bft_data["cookies"]:
        host = c["host_key"].lstrip(".")
        cookie_map[host] = {
            "host": host,
            "name": c["name"],
            "has_value": True,
            "source": "bft",
        }

    for c in passview_data["cookies"]:
        host = c["host_key"].lstrip(".")
        if host not in cookie_map:
            cookie_map[host] = {
                "host": host,
                "name": c["name"],
                "has_value": False,
                "source": "passview",
            }

    # ── Final URL list ───────────────────────────────────────────────
    all_urls = list(url_map.values())

    # ── Indicators ───────────────────────────────────────────────────
    indicators = {
        "total_unique_urls": len(all_urls),
        "login_url_count": sum(1 for u in all_urls if u["is_login_url"]),
        "download_count": len(downloads),
        "cookie_count": len(cookie_map),
        "multi_source_url_count": sum(1 for u in all_urls if len(u["sources"]) > 1),
        "confirmed_phishing_visit_count": sum(
            1 for u in all_urls
            if u["is_login_url"] and "history" in u["sources"]
        ),
        "download_url_count": sum(1 for u in all_urls if u["is_download_url"]),
    }

    normalized = {
        "schema_version": "1.0",
        "category": "browser",
        "case_id": case_id,
        "source_file": source_file,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tools_used": ["browserhistoryview_or_hindsight", "bft", "webbrowserpassview"],
        "indicators": indicators,
        "urls": all_urls,
        "downloads": downloads,
        "cookies": list(cookie_map.values()),
        "login_urls": [
            {"origin_url": e["origin_url"], "username": e["username"]}
            for e in passview_data["logins"]
        ],
        "raw_findings": {
            "history": history_data,
            "bft": bft_data,
            "passview": passview_data,
        },
    }

    return normalized


def save_normalized_case(normalized: dict[str, Any], output_dir: str) -> str:
    """Save normalized JSON to disk. Returns the saved path."""
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{normalized['case_id']}_browser_normalized.json"
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2, ensure_ascii=False)
    return path


if __name__ == "__main__":
    import json as _json
    print("Run from browser_normalizer directly — use normalize_browser_case() in your code.")
