"""
tshark_flow_fields.py
───────────────────────
This is an ADDITIONAL tshark invocation (not a replacement for tshark_tool.py's
existing IP/port summary). It pulls the RAW per-packet fields needed to build
CICIDS-style per-flow features.

WHY a separate command:
tshark_tool.py's existing command:
    tshark -r file.pcap -T fields -e ip.src -e ip.dst -e tcp.dstport
...only gives 3 fields, fine for the IP/port summary report. To compute
Flow Duration / Bytes-per-sec / flag counts we need timestamps, lengths,
ports (both directions), and TCP flags per packet.

The new command (run this from tools/tshark_tool.py or call separately):

    tshark -r <pcap> -T fields \
        -e frame.time_epoch \
        -e ip.src -e ip.dst \
        -e tcp.srcport -e tcp.dstport \
        -e frame.len \
        -e tcp.flags.syn -e tcp.flags.reset -e tcp.flags.push -e tcp.flags.ack \
        -E separator=,

Each output line has 10 comma-separated fields:
    time_epoch,src_ip,dst_ip,src_port,dst_port,length,syn,rst,psh,ack

Example:
    1751234567.123456,10.0.0.5,185.220.101.50,54321,443,1420,0,0,1,1

Usage:
    from feature_extraction.tshark_flow_fields import build_flows
    flows = build_flows(raw_tshark_csv_text)
"""

from __future__ import annotations
from typing import Any


TSHARK_FLOW_FIELDS_CMD_TEMPLATE = (
    'tshark -r "{filepath}" -T fields '
    '-e frame.time_epoch '
    '-e ip.src -e ip.dst '
    '-e tcp.srcport -e tcp.dstport '
    '-e frame.len '
    '-e tcp.flags.syn -e tcp.flags.reset -e tcp.flags.push -e tcp.flags.ack '
    '-E separator=,'
)


def _flow_key(src_ip: str, src_port: str, dst_ip: str, dst_port: str) -> tuple:
    """
    Bidirectional flow key — same (src,dst) pair in either direction belongs
    to the same flow, matching CICFlowMeter's flow definition.
    We pick the "first seen" direction as forward (fwd) and the reverse as
    backward (bwd), exactly like CICFlowMeter does.
    """
    return tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))


def build_flows(raw_csv_text: str) -> dict[tuple, dict[str, Any]]:
    """
    Parses tshark CSV output where each line has 10 comma-separated fields:
        time, src_ip, dst_ip, src_port, dst_port, length, syn, rst, psh, ack

    Groups packets into bidirectional flows and tags each packet with its
    direction ("fwd" or "bwd") relative to the first-seen direction of that flow.
    """
    flows: dict[tuple, dict[str, Any]] = {}

    for line in raw_csv_text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(",")
        if len(parts) != 10:
            continue

        try:
            pkt_time = float(parts[0])
            src_ip, dst_ip = parts[1], parts[2]
            src_port, dst_port = parts[3], parts[4]
            length = int(parts[5]) if parts[5] else 0
            syn = int(parts[6]) if parts[6] else 0
            rst = int(parts[7]) if parts[7] else 0
            psh = int(parts[8]) if parts[8] else 0
            ack = int(parts[9]) if parts[9] else 0
        except ValueError:
            continue

        if not src_ip or not dst_ip or not src_port or not dst_port:
            continue

        key = _flow_key(src_ip, src_port, dst_ip, dst_port)

        if key not in flows:
            flows[key] = {
                "packets": [],
                "fwd_src_ip": src_ip,
                "fwd_src_port": src_port,
                "fwd_dst_ip": dst_ip,
                "fwd_dst_port": dst_port,
            }

        f = flows[key]
        direction = "fwd" if (src_ip == f["fwd_src_ip"] and src_port == f["fwd_src_port"]) else "bwd"

        f["packets"].append({
            "time": pkt_time,
            "length": length,
            "syn": syn,
            "rst": rst,
            "psh": psh,
            "ack": ack,
            "direction": direction,
        })

    return flows


if __name__ == "__main__":
    sample_csv = """1751234567.100000,10.0.0.5,185.220.101.50,54321,443,1420,0,0,1,1
1751234567.150000,185.220.101.50,10.0.0.5,443,54321,60,0,0,0,1
1751234567.200000,10.0.0.5,185.220.101.50,54321,443,1420,0,0,1,1
1751234567.250000,185.220.101.50,10.0.0.5,443,54321,60,0,0,0,1
1751234560.000000,192.168.1.100,10.0.0.5,64650,22,40,1,0,0,0
"""
    flows = build_flows(sample_csv)
    for key, flow in flows.items():
        print(f"Flow {key}: {len(flow['packets'])} packets")
