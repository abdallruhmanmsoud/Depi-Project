"""
tcpflow_parser.py
──────────────────
Parses the RAW TERMINAL OUTPUT produced by tools/tcpflow_tool.py
(the 4 steps: reconstruct flows / ls listing / credential grep / HTTP grep)
and converts it into structured Python data.

Key insight: tcpflow names each reconstructed flow file as
    <src_ip>.<src_port>-<dst_ip>.<dst_port>
e.g. "010.000.000.005.54321-185.220.101.050.00443"
The IP octets and ports are zero-padded, so we un-pad them.

This is what lets us detect:
  - Data exfiltration  → unusually large flow file size
  - C2 beaconing        → many small flows to the same dst_ip:dst_port
  - Credential exposure → flows matched by Step 3 grep
  - Plaintext HTTP      → flows matched by Step 4 grep (even "binary file matches"
                           still tells us THAT file contains the pattern)

Usage:
    from parsing.tcpflow_parser import parse_tcpflow_output
    data = parse_tcpflow_output(raw_text)
"""

from __future__ import annotations
import re
from typing import Any


# Matches a tcpflow-style flow filename, e.g.:
#   010.000.000.005.54321-185.220.101.050.00443
FLOW_FILENAME_RE = re.compile(
    r"^(?P<src_ip>\d{3}\.\d{3}\.\d{3}\.\d{3})\.(?P<src_port>\d{5})"
    r"-"
    r"(?P<dst_ip>\d{3}\.\d{3}\.\d{3}\.\d{3})\.(?P<dst_port>\d{5})$"
)

# Matches an `ls -lh` line, e.g.:
#   -rw-rw-r-- 1 mohamed mohamed   83K Jun 30 02:32 010.000.000.005.54321-185.220.101.050.00443
LS_LINE_RE = re.compile(
    r"^[-dlrwx]{10}\s+\d+\s+\S+\s+\S+\s+(?P<size>[\d.]+[KMG]?)\s+"
    r"\S+\s+\d+\s+[\d:]+\s+(?P<filename>\S+)$"
)


def _unpad_ip(padded_ip: str) -> str:
    """'010.000.000.005' -> '10.0.0.5'"""
    return ".".join(str(int(octet)) for octet in padded_ip.split("."))


def _unpad_port(padded_port: str) -> int:
    """'00443' -> 443"""
    return int(padded_port)


def _size_to_bytes(size_str: str) -> int:
    """Convert ls -lh size strings ('83K', '303', '1.2M') to raw bytes (approx)."""
    size_str = size_str.strip()
    multipliers = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
    if size_str and size_str[-1] in multipliers:
        try:
            return int(float(size_str[:-1]) * multipliers[size_str[-1]])
        except ValueError:
            return 0
    try:
        return int(size_str)
    except ValueError:
        return 0


def parse_tcpflow_output(raw_text: str) -> dict[str, Any]:
    """
    Parse tcpflow tool's raw multi-step terminal output into structured data.

    Returns
    -------
    dict with keys:
        flows: [{src_ip, src_port, dst_ip, dst_port, size_bytes, size_human,
                 has_credentials, has_http}]
        ignored_syns: [{src_ip, src_port, dst_ip, dst_port}]   # scan/brute-force noise
        flow_count: int
        largest_flow: {...} | None       -> likely exfiltration candidate
        repeated_dst_pairs: [{dst_ip, dst_port, flow_count}]   -> likely beaconing
        credential_flow_count: int
        http_flow_count: int
    """
    data: dict[str, Any] = {
        "flows": [],
        "ignored_syns": [],
        "flow_count": 0,
        "largest_flow": None,
        "repeated_dst_pairs": [],
        "credential_flow_count": 0,
        "http_flow_count": 0,
    }

    # ---- Parse "SYN TO IGNORE" lines (Step 1) ----
    # SYN TO IGNORE! SYN tcp=... flow=flow[192.168.1.100:64650->10.0.0.5:22]
    for m in re.finditer(
        r"SYN TO IGNORE.*?flow\[([\d.]+):(\d+)->([\d.]+):(\d+)\]", raw_text
    ):
        data["ignored_syns"].append({
            "src_ip": m.group(1),
            "src_port": int(m.group(2)),
            "dst_ip": m.group(3),
            "dst_port": int(m.group(4)),
        })

    # ---- Parse `ls -lh` flow file listing (Step 2) ----
    flows_by_filename: dict[str, dict[str, Any]] = {}
    for line in raw_text.splitlines():
        ls_match = LS_LINE_RE.match(line.strip())
        if not ls_match:
            continue
        filename = ls_match.group("filename")
        fname_match = FLOW_FILENAME_RE.match(filename)
        if not fname_match:
            continue  # not a flow file (e.g. report.xml)

        size_bytes = _size_to_bytes(ls_match.group("size"))
        flow = {
            "filename": filename,
            "src_ip": _unpad_ip(fname_match.group("src_ip")),
            "src_port": _unpad_port(fname_match.group("src_port")),
            "dst_ip": _unpad_ip(fname_match.group("dst_ip")),
            "dst_port": _unpad_port(fname_match.group("dst_port")),
            "size_bytes": size_bytes,
            "size_human": ls_match.group("size"),
            "has_credentials": False,
            "has_http": False,
        }
        flows_by_filename[filename] = flow

    # ---- Parse Step 3: credential grep results ----
    # grep -rl ... lists matching FILE PATHS, one per line
    cred_section = _extract_section(raw_text, "Searching for credentials", "HTTP content extraction")
    for line in cred_section.splitlines():
        line = line.strip()
        for filename in flows_by_filename:
            if filename in line:
                flows_by_filename[filename]["has_credentials"] = True

    # ---- Parse Step 4: HTTP content grep results ----
    # Lines look like:
    #   grep: <path>/<filename>: binary file matches
    #   <path>/<filename>:<matched line>            (for text files)
    http_section = _extract_section(raw_text, "HTTP content extraction", None)
    for line in http_section.splitlines():
        for filename in flows_by_filename:
            if filename in line:
                flows_by_filename[filename]["has_http"] = True

    flows = list(flows_by_filename.values())
    data["flows"] = flows
    data["flow_count"] = len(flows)
    data["credential_flow_count"] = sum(1 for f in flows if f["has_credentials"])
    data["http_flow_count"] = sum(1 for f in flows if f["has_http"])

    # ---- Largest flow = strong exfiltration signal ----
    if flows:
        data["largest_flow"] = max(flows, key=lambda f: f["size_bytes"])

    # ---- Repeated (dst_ip, dst_port) pairs = beaconing signal ----
    pair_counts: dict[tuple[str, int], int] = {}
    for f in flows:
        key = (f["dst_ip"], f["dst_port"])
        pair_counts[key] = pair_counts.get(key, 0) + 1

    repeated = [
        {"dst_ip": ip, "dst_port": port, "flow_count": count}
        for (ip, port), count in pair_counts.items()
        if count >= 2
    ]
    repeated.sort(key=lambda x: x["flow_count"], reverse=True)
    data["repeated_dst_pairs"] = repeated

    return data


def _extract_section(text: str, start_marker: str, end_marker: str | None) -> str:
    start_match = re.search(re.escape(start_marker), text)
    if not start_match:
        return ""
    start_idx = start_match.end()
    if end_marker:
        end_match = re.search(re.escape(end_marker), text[start_idx:])
        if end_match:
            return text[start_idx: start_idx + end_match.start()]
    return text[start_idx:]


if __name__ == "__main__":
    sample = """
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
grep: /home/.../010.000.000.002.49185-001.001.001.001.00080: binary file matches
tcpflow analysis complete.
"""
    import json
    result = parse_tcpflow_output(sample)
    print(json.dumps(result, indent=2))
