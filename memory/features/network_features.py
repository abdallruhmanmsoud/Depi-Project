"""
Network Feature Extractor
==========================
Extracts behavioral features from normalized network connection data.

DFIR Rationale:
  - Outbound connections to non-standard ports indicate C2 channels
  - High numbers of unique remote hosts indicate scanning or exfiltration
  - ESTABLISHED connections show active C2 sessions
  - LISTENING sockets may indicate backdoors or bind shells
  - IPv6 connections are sometimes used to evade monitoring
  - Connections from system processes to external IPs are suspicious
  - Port distribution reveals scanning behavior

Handles empty datasets safely (netscan often returns 0 results).
"""

import math
from collections import Counter


# Common legitimate ports (inbound and outbound)
COMMON_PORTS = {
    0, 53, 67, 68, 80, 88, 123, 135, 137, 138, 139,
    389, 443, 445, 464, 500, 636, 993, 995,
    3389, 5353, 5985, 5986, 8080, 8443,
}

# RFC 1918 private address prefixes
PRIVATE_PREFIXES = [
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
    "0.0.0.0",
    "::",
    "::1",
    "*",
    "",
]

# Connection states
ACTIVE_STATES = {"ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2"}


class NetworkFeatureExtractor:

    def extract(self, connections: list) -> dict:

        if not connections:
            return self._empty_features()

        total = len(connections)
        per_process = Counter()
        protocol_counter = Counter()
        state_counter = Counter()
        remote_hosts = set()
        remote_ports = Counter()
        local_ports = Counter()

        external_count = 0
        listening_count = 0
        established_count = 0
        uncommon_port_count = 0
        ipv6_count = 0

        for conn in connections:
            pid = conn["pid"]
            proto = conn.get("protocol", "")
            local_addr = conn.get("local_addr", "") or ""
            local_port = conn.get("local_port", 0) or 0
            foreign_addr = conn.get("foreign_addr", "") or ""
            foreign_port = conn.get("foreign_port", 0) or 0
            state = conn.get("state", "") or ""

            per_process[pid] += 1
            protocol_counter[proto] += 1
            state_counter[state] += 1
            local_ports[local_port] += 1

            # ── External vs internal ──
            is_external = not any(foreign_addr.startswith(p) for p in PRIVATE_PREFIXES)
            if is_external and foreign_addr:
                external_count += 1
                remote_hosts.add(foreign_addr)
                remote_ports[foreign_port] += 1

            # ── State analysis ──
            if state.upper() == "LISTENING":
                listening_count += 1
            if state.upper() == "ESTABLISHED":
                established_count += 1

            # ── Uncommon ports ──
            if foreign_port and foreign_port not in COMMON_PORTS:
                uncommon_port_count += 1

            # ── IPv6 ──
            if "v6" in proto.lower() or ":" in foreign_addr:
                ipv6_count += 1

        # ── Per-process statistics ──
        counts = list(per_process.values())
        unique_procs = len(per_process)
        avg_per_proc = sum(counts) / unique_procs if unique_procs > 0 else 0.0
        max_per_proc = max(counts) if counts else 0

        # ── Ratios ──
        external_ratio = external_count / total if total > 0 else 0.0
        listening_ratio = listening_count / total if total > 0 else 0.0
        tcp_count = sum(v for k, v in protocol_counter.items() if "tcp" in k.lower())
        udp_count = sum(v for k, v in protocol_counter.items() if "udp" in k.lower())

        return {
            # ── Counts ──
            "net_total_connections":        total,
            "net_unique_process_count":     unique_procs,
            "net_tcp_count":                tcp_count,
            "net_udp_count":                udp_count,
            "net_ipv6_count":               ipv6_count,

            # ── Direction ──
            "net_external_count":           external_count,
            "net_external_ratio":           round(external_ratio, 4),
            "net_unique_remote_hosts":      len(remote_hosts),
            "net_unique_remote_ports":      len(remote_ports),

            # ── State ──
            "net_established_count":        established_count,
            "net_listening_count":          listening_count,
            "net_listening_ratio":          round(listening_ratio, 4),

            # ── Anomaly ──
            "net_uncommon_port_count":      uncommon_port_count,

            # ── Per-process ──
            "net_per_process_avg":          round(avg_per_proc, 4),
            "net_per_process_max":          max_per_proc,
        }

    def _empty_features(self) -> dict:
        keys = [
            "net_total_connections", "net_unique_process_count",
            "net_tcp_count", "net_udp_count", "net_ipv6_count",
            "net_external_count", "net_external_ratio",
            "net_unique_remote_hosts", "net_unique_remote_ports",
            "net_established_count", "net_listening_count",
            "net_listening_ratio",
            "net_uncommon_port_count",
            "net_per_process_avg", "net_per_process_max",
        ]
        return {k: 0 for k in keys}
