"""
feature_extractor.py
──────────────────────
Converts grouped flow packets (from tshark_flow_fields.build_flows) into
numeric feature vectors matching a SUBSET of the CICIDS2017 schema.

We deliberately use only the 15 features listed below — these are the ones
we can reliably compute from live tshark output without needing the full
CICFlowMeter tool (which is far heavier and out of scope before the deadline).

FEATURE_NAMES order is FIXED and must match train_baseline.py exactly,
since the saved Isolation Forest model expects columns in this order.

Usage:
    from feature_extraction.tshark_flow_fields import build_flows
    from feature_extraction.feature_extractor import extract_features_for_flow, FEATURE_NAMES

    flows = build_flows(raw_tshark_csv)
    for key, flow in flows.items():
        vector = extract_features_for_flow(flow)   # -> list[float], order = FEATURE_NAMES
"""

from __future__ import annotations
from typing import Any


# ── Fixed feature order — MUST match train_baseline.py's CICIDS column selection ──
FEATURE_NAMES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Down/Up Ratio",
]


def extract_features_for_flow(flow: dict[str, Any]) -> list[float]:
    """
    Compute the 15-feature CICIDS-style vector for a single flow.

    Returns list[float] in the exact order of FEATURE_NAMES.
    """
    packets = flow["packets"]
    if not packets:
        return [0.0] * len(FEATURE_NAMES)

    fwd_packets = [p for p in packets if p["direction"] == "fwd"]
    bwd_packets = [p for p in packets if p["direction"] == "bwd"]

    times = [p["time"] for p in packets]
    flow_duration_s = max(times) - min(times) if len(times) > 1 else 0.0
    flow_duration_us = flow_duration_s * 1_000_000  # CICIDS uses microseconds

    total_fwd_packets = len(fwd_packets)
    total_bwd_packets = len(bwd_packets)
    total_len_fwd = sum(p["length"] for p in fwd_packets)
    total_len_bwd = sum(p["length"] for p in bwd_packets)
    total_bytes = total_len_fwd + total_len_bwd
    total_packets = total_fwd_packets + total_bwd_packets

    # Avoid division by zero (single-packet flows have duration=0)
    duration_for_rate = flow_duration_s if flow_duration_s > 0 else 1.0

    flow_bytes_per_s   = total_bytes          / duration_for_rate
    flow_packets_per_s = total_packets        / duration_for_rate
    fwd_packets_per_s  = total_fwd_packets    / duration_for_rate
    bwd_packets_per_s  = total_bwd_packets    / duration_for_rate

    syn_count = sum(p["syn"] for p in packets)
    rst_count = sum(p["rst"] for p in packets)
    psh_count = sum(p["psh"] for p in packets)
    ack_count = sum(p["ack"] for p in packets)

    down_up_ratio = (
        total_bwd_packets / total_fwd_packets if total_fwd_packets > 0 else 0.0
    )

    dst_port = float(flow.get("fwd_dst_port", 0) or 0)

    return [
        dst_port,
        flow_duration_us,
        float(total_fwd_packets),
        float(total_bwd_packets),
        float(total_len_fwd),
        float(total_len_bwd),
        flow_bytes_per_s,
        flow_packets_per_s,
        fwd_packets_per_s,
        bwd_packets_per_s,
        float(syn_count),
        float(rst_count),
        float(psh_count),
        float(ack_count),
        down_up_ratio,
    ]


def extract_features_for_all_flows(
    flows: dict[tuple, dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Run extract_features_for_flow on every flow in a flows dict.

    Returns list of {flow_key, src, dst, features: list[float]}
    """
    results = []
    for key, flow in flows.items():
        vector = extract_features_for_flow(flow)
        results.append({
            "flow_key": key,
            "src": f"{flow['fwd_src_ip']}:{flow['fwd_src_port']}",
            "dst": f"{flow['fwd_dst_ip']}:{flow['fwd_dst_port']}",
            "features": vector,
        })
    return results


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from feature_extraction.tshark_flow_fields import build_flows

    sample_csv = """1751234567.100000,10.0.0.5,185.220.101.50,54321,443,1420,0,0,1,1
1751234567.150000,185.220.101.50,10.0.0.5,443,54321,60,0,0,0,1
1751234567.200000,10.0.0.5,185.220.101.50,54321,443,1420,0,0,1,1
1751234567.250000,185.220.101.50,10.0.0.5,443,54321,60,0,0,0,1
"""
    flows = build_flows(sample_csv)
    for r in extract_features_for_all_flows(flows):
        print(f"\nFlow: {r['src']} -> {r['dst']}")
        for name, val in zip(FEATURE_NAMES, r["features"]):
            print(f"  {name}: {val}")
