"""
tshark_parser.py
─────────────────
Parses the RAW TEXT REPORT produced by tools/tshark_tool.py
(the human-readable report with emojis: 📊 🌐 🔌 🚨 🌍 🧠)
and converts it into a structured Python dict.

This does NOT re-run tshark — it parses the *report text* that
TsharkTool.run() already produced (the StepResult with command="(analysis)",
or the .txt report file saved to disk).

Usage:
    from parsing.tshark_parser import parse_tshark_report
    data = parse_tshark_report(report_text)
"""

from __future__ import annotations
import re
from typing import Any


def parse_tshark_report(report_text: str) -> dict[str, Any]:
    """
    Parse TShark tool's formatted text report into structured data.

    Returns
    -------
    dict with keys:
        total_packets, unique_ips, unique_ports,
        top_ips: [{ip, connections}],
        top_ports: [{port, count}],
        suspicious_ports: [{port, count}],
        suspicious_ips: [{ip, connections}],
        external_ip_count,
        insights: [str]
    """
    data: dict[str, Any] = {
        "total_packets": 0,
        "unique_ips": 0,
        "unique_ports": 0,
        "top_ips": [],
        "top_ports": [],
        "suspicious_ports": [],
        "suspicious_ips": [],
        "external_ip_count": 0,
        "insights": [],
    }

    # ---- Summary numbers ----
    m = re.search(r"Total Packets:\s*(\d+)", report_text)
    if m:
        data["total_packets"] = int(m.group(1))

    m = re.search(r"Unique IPs:\s*(\d+)", report_text)
    if m:
        data["unique_ips"] = int(m.group(1))

    m = re.search(r"Unique Ports:\s*(\d+)", report_text)
    if m:
        data["unique_ports"] = int(m.group(1))

    # ---- Top Active IPs ----
    # Format: "10.0.0.5 → 1013 connections"
    top_ips_section = _extract_section(report_text, "Top Active IPs", "Top Ports")
    for line in top_ips_section.splitlines():
        m = re.match(r"\s*([\d.]+)\s*→\s*(\d+)\s*connections", line)
        if m:
            data["top_ips"].append({
                "ip": m.group(1),
                "connections": int(m.group(2)),
            })

    # ---- Top Ports ----
    # Format: "Port 80 → 539 times"
    top_ports_section = _extract_section(report_text, "Top Ports", "Suspicious Ports")
    for line in top_ports_section.splitlines():
        m = re.match(r"\s*Port\s+(\d+)\s*→\s*(\d+)\s*times", line)
        if m:
            data["top_ports"].append({
                "port": int(m.group(1)),
                "count": int(m.group(2)),
            })

    # ---- Suspicious Ports ----
    # Format: "⚠️ Port 20 used 1 times"
    susp_ports_section = _extract_section(report_text, "Suspicious Ports", "Suspicious IPs")
    for line in susp_ports_section.splitlines():
        m = re.search(r"Port\s+(\d+)\s+used\s+(\d+)\s+times", line)
        if m:
            data["suspicious_ports"].append({
                "port": int(m.group(1)),
                "count": int(m.group(2)),
            })

    # ---- Suspicious IPs ----
    # Format: "⚠️ 10.0.0.5 → 1013 connections (High Activity)"
    susp_ips_section = _extract_section(report_text, "Suspicious IPs", "External Connections")
    for line in susp_ips_section.splitlines():
        m = re.search(r"([\d.]+)\s*→\s*(\d+)\s*connections", line)
        if m:
            data["suspicious_ips"].append({
                "ip": m.group(1),
                "connections": int(m.group(2)),
            })

    # ---- External Connections ----
    m = re.search(r"External IPs detected:\s*(\d+)", report_text)
    if m:
        data["external_ip_count"] = int(m.group(1))

    # ---- Quick Insights ----
    insights_section = _extract_section(report_text, "Quick Insights", None)
    for line in insights_section.splitlines():
        line = line.strip()
        if line and not line.startswith("==="):
            data["insights"].append(line)

    return data


def _extract_section(text: str, start_marker: str, end_marker: str | None) -> str:
    """Extract the text between two section headers (both optional emoji-prefixed)."""
    start_pattern = re.escape(start_marker)
    start_match = re.search(start_pattern, text)
    if not start_match:
        return ""
    start_idx = start_match.end()

    if end_marker:
        end_pattern = re.escape(end_marker)
        end_match = re.search(end_pattern, text[start_idx:])
        if end_match:
            return text[start_idx: start_idx + end_match.start()]

    return text[start_idx:]


if __name__ == "__main__":
    sample = """
📊 === Analysis Summary ===
Total Packets: 1674
Unique IPs: 23
Unique Ports: 567

🌐 === Top Active IPs ===
10.0.0.5 → 1013 connections
8.8.8.8 → 133 connections
142.250.80.46 → 113 connections
1.1.1.1 → 100 connections
185.220.101.50 → 92 connections

🔌 === Top Ports ===
Port 80 → 539 times
Port 22 → 240 times
Port 443 → 151 times
Port 53 → 121 times
Port 8080 → 30 times

🚨 === Suspicious Ports ===
⚠️ Port 20 used 1 times
⚠️ Port 23 used 1 times
⚠️ Port 26 used 1 times
⚠️ Port 29 used 1 times
⚠️ Port 32 used 1 times

🚨 === Suspicious IPs ===
⚠️ 10.0.0.5 → 1013 connections (High Activity)
⚠️ 8.8.8.8 → 133 connections (High Activity)
⚠️ 142.250.80.46 → 113 connections (High Activity)

🌍 === External Connections ===
External IPs detected: 5

🧠 === Quick Insights ===
Possible unusual ports detected (malware or tunneling).
High-frequency communication detected (possible beaconing or scanning).
TShark analysis complete.
"""
    import json
    result = parse_tshark_report(sample)
    print(json.dumps(result, indent=2))
