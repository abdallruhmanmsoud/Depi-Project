"""
network_normalizer.py
───────────────────────
Combines the structured outputs of tshark_parser + tcpflow_parser into a
SINGLE normalized JSON, matching the "1. INPUT — Normalized JSON" stage
of the AI Layer architecture (ai_engine/network/normalization/).

This is the artifact that feeds into:
    Feature Extraction → Preprocessing → Isolation Forest → Differential
    Analysis → MITRE Mapping → Explanation → Final Output

Design notes
------------
- We DO NOT throw away tool-specific detail; we fold it into
  `raw_findings` so the Feature Extraction stage can still reach it.
- We DO produce a flat, ML-friendly `indicators` block, since Isolation
  Forest needs numeric/categorical features, not nested tool reports.
- `events` is a normalized list of discrete suspicious occurrences,
  each taggable with a MITRE technique later by the mapping stage.

Usage:
    from normalization.network_normalizer import normalize_network_case
    normalized = normalize_network_case(
        tshark_report_text=...,
        tcpflow_raw_text=...,
        case_id="case_001",
        source_file="malicious_network_traffic.pcap",
    )
"""

from __future__ import annotations
import sys
import os
import json
from datetime import datetime, timezone
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsing.tshark_parser import parse_tshark_report
from parsing.tcpflow_parser import parse_tcpflow_output


# ── Thresholds (tunable; mirrors config.yaml threshold style from architecture) ──
EXFIL_SIZE_BYTES_THRESHOLD = 10_000        # flows above this = possible exfiltration
HIGH_ACTIVITY_CONN_THRESHOLD = 100         # matches tshark_tool.py's own suspicious_ips rule
COMMON_PORTS = {80, 443, 53}               # excluded from beaconing detection (normal web/DNS noise)


def normalize_network_case(
    tshark_report_text: str,
    tcpflow_raw_text: str,
    case_id: str,
    source_file: str,
) -> dict[str, Any]:
    """
    Build the normalized Network JSON for one forensic case.

    Parameters
    ----------
    tshark_report_text : raw text from TsharkTool's "(analysis)" StepResult
    tcpflow_raw_text    : raw combined terminal output from TcpflowTool
    case_id             : unique case/session identifier (e.g. dashboard upload session id)
    source_file         : original pcap filename

    Returns
    -------
    Normalized JSON dict, ready to be written to
    ai_engine/network/normalization/<case_id>_network_normalized.json
    """
    tshark_data = parse_tshark_report(tshark_report_text)
    tcpflow_data = parse_tcpflow_output(tcpflow_raw_text)

    events: list[dict[str, Any]] = []

    # ── 1. Port scan detection (many distinct low-count suspicious ports + ignored SYNs) ──
    if len(tshark_data["suspicious_ports"]) >= 3 or len(tcpflow_data["ignored_syns"]) >= 2:
        scanned_ports = sorted({p["port"] for p in tshark_data["suspicious_ports"]})
        events.append({
            "event_type": "port_scan",
            "confidence": "medium" if len(tshark_data["suspicious_ports"]) < 10 else "high",
            "src_ips": sorted({s["src_ip"] for s in tcpflow_data["ignored_syns"]}) or None,
            "evidence": {
                "suspicious_port_count": len(tshark_data["suspicious_ports"]),
                "sample_ports": scanned_ports[:10],
                "incomplete_tcp_handshakes": len(tcpflow_data["ignored_syns"]),
            },
        })

    # ── 2. SYN flood / DDoS detection (single port, very high hit count) ──
    for port_entry in tshark_data["top_ports"]:
        if port_entry["port"] == 80 and port_entry["count"] > HIGH_ACTIVITY_CONN_THRESHOLD * 3:
            events.append({
                "event_type": "syn_flood_ddos",
                "confidence": "high",
                "dst_port": port_entry["port"],
                "evidence": {"packet_count": port_entry["count"]},
            })

    # ── 3. SSH brute force (repeated incomplete handshakes to port 22) ──
    ssh_ignored = [s for s in tcpflow_data["ignored_syns"] if s["dst_port"] == 22]
    ssh_top = next((p for p in tshark_data["top_ports"] if p["port"] == 22), None)
    if ssh_ignored or (ssh_top and ssh_top["count"] > 50):
        events.append({
            "event_type": "ssh_brute_force",
            "confidence": "high" if ssh_ignored else "medium",
            "dst_port": 22,
            "src_ips": sorted({s["src_ip"] for s in ssh_ignored}) or None,
            "evidence": {
                "incomplete_handshakes": len(ssh_ignored),
                "total_port_22_packets": ssh_top["count"] if ssh_top else None,
            },
        })

    # ── 4. Data exfiltration (oversized reconstructed flow to external IP) ──
    largest = tcpflow_data["largest_flow"]
    if largest and largest["size_bytes"] >= EXFIL_SIZE_BYTES_THRESHOLD:
        events.append({
            "event_type": "data_exfiltration",
            "confidence": "high",
            "src_ip": largest["src_ip"],
            "dst_ip": largest["dst_ip"],
            "dst_port": largest["dst_port"],
            "evidence": {
                "flow_size_bytes": largest["size_bytes"],
                "flow_size_human": largest["size_human"],
                "filename": largest["filename"],
            },
        })

    # ── 5. C2 beaconing (repeated flows to same non-standard dst_ip:dst_port) ──
    # Only non-standard ports count as beaconing — repeated hits on 80/443/53
    # from many DIFFERENT src hosts is normal web/DNS traffic, not beaconing.
    NONSTANDARD_REPEAT_THRESHOLD = 2
    for pair in tcpflow_data["repeated_dst_pairs"]:
        if pair["dst_port"] not in COMMON_PORTS and pair["flow_count"] >= NONSTANDARD_REPEAT_THRESHOLD:
            events.append({
                "event_type": "c2_beaconing",
                "confidence": "high",
                "dst_ip": pair["dst_ip"],
                "dst_port": pair["dst_port"],
                "evidence": {"repeated_flow_count": pair["flow_count"]},
            })

    # ── 6. High-activity / anomalous hosts (from tshark's own suspicious_ips) ──
    for ip_entry in tshark_data["suspicious_ips"]:
        events.append({
            "event_type": "high_activity_host",
            "confidence": "low",
            "ip": ip_entry["ip"],
            "evidence": {"connection_count": ip_entry["connections"]},
        })

    # ── Build flat ML-ready indicators block ──
    indicators = {
        "total_packets": tshark_data["total_packets"],
        "unique_ip_count": tshark_data["unique_ips"],
        "unique_port_count": tshark_data["unique_ports"],
        "external_ip_count": tshark_data["external_ip_count"],
        "suspicious_port_count": len(tshark_data["suspicious_ports"]),
        "suspicious_ip_count": len(tshark_data["suspicious_ips"]),
        "reconstructed_flow_count": tcpflow_data["flow_count"],
        "incomplete_handshake_count": len(tcpflow_data["ignored_syns"]),
        "max_flow_size_bytes": largest["size_bytes"] if largest else 0,
        "credential_exposed_flow_count": tcpflow_data["credential_flow_count"],
        "http_plaintext_flow_count": tcpflow_data["http_flow_count"],
        "max_repeated_dst_pair_count": (
            tcpflow_data["repeated_dst_pairs"][0]["flow_count"]
            if tcpflow_data["repeated_dst_pairs"] else 0
        ),
        "event_type_count": len(events),
    }

    normalized = {
        "schema_version": "1.0",
        "category": "network",
        "case_id": case_id,
        "source_file": source_file,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tools_used": ["tshark", "tcpflow"],
        "indicators": indicators,
        "events": events,
        "raw_findings": {
            "tshark": tshark_data,
            "tcpflow": tcpflow_data,
        },
    }

    return normalized


def save_normalized_case(normalized: dict[str, Any], output_dir: str) -> str:
    """Save normalized JSON to disk using the case_id as filename. Returns the path."""
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{normalized['case_id']}_network_normalized.json"
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2, ensure_ascii=False)
    return path


if __name__ == "__main__":
    # Self-test using the real dashboard outputs from this conversation
    tshark_sample = """
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

    tcpflow_sample = """
[Step 1/4] Reconstructing TCP flows ...
SYN TO IGNORE! SYN tcp=0x1 flow=flow[192.168.1.100:64650->10.0.0.5:22]
SYN TO IGNORE! SYN tcp=0x2 flow=flow[192.168.1.100:57755->10.0.0.5:22]
[Step 2/4] Listing reconstructed flows ...
total 988K
-rw-rw-r-- 1 mohamed mohamed   38 Jun 30 02:32 010.000.000.002.49185-001.001.001.001.00080
-rw-rw-r-- 1 mohamed mohamed  83K Jun 30 02:32 010.000.000.005.54321-185.220.101.050.00443
-rw-rw-r-- 1 mohamed mohamed  303 Jun 30 02:32 010.000.000.005.55000-185.220.101.050.08080
[Step 3/4] Searching for credentials ...
/home/.../tcpflow_out/report.xml
[Step 4/4] HTTP content extraction ...
grep: /home/.../010.000.000.004.62915-142.250.080.046.00080: binary file matches
tcpflow analysis complete.
"""

    result = normalize_network_case(
        tshark_report_text=tshark_sample,
        tcpflow_raw_text=tcpflow_sample,
        case_id="case_demo_001",
        source_file="malicious_network_traffic.pcap",
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))
