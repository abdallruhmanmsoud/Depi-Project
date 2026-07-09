"""
TShark Network Analysis module.
Analyzes PCAP files to detect suspicious network activity.
"""

from __future__ import annotations

import os
from typing import Callable
from collections import Counter


from tools.base import BaseTool, StepResult


class TsharkTool(BaseTool):
    tool_id = "tshark"
    name = "TShark Network Analyzer"
    description = (
        "Analyze PCAP files using tshark to extract network connections, "
        "detect suspicious ports, and identify abnormal traffic patterns."
    )
    accepted_extensions: list[str] = [".pcap", ".pcapng"]
    system_prerequisites = ["tshark"]

    def run(
        self,
        filepath: str,
        emit: Callable[[str], None] | None = None,
    ) -> list[StepResult]:

        results: list[StepResult] = []
        basename = os.path.basename(filepath)

        # Step 1 — check tshark
        if emit:
            emit("[Step 1/3] Checking TShark installation ...")

        step = self._exec("tshark --version", emit)
        results.append(step)

        # Step 2 — extract data
        if emit:
            emit(f"[Step 2/3] Extracting network data from {basename} ...")

        cmd = (
            f"tshark -r \"{filepath}\" "
            "-T fields -e ip.src -e ip.dst -e tcp.dstport"
        )

        step = self._exec(cmd, None)  # ❌ منع عرض raw output
        results.append(step)

        if not step.success:
            if emit:
                emit("Failed to extract network data.")
            return results

        lines = step.output.splitlines()

        ports = []
        ips = []

        for line in lines:
            parts = line.split("\t")
            if len(parts) == 3:
                _, dst, port = parts

                if port:
                    ports.append(port)

                if dst:
                    ips.append(dst)

        # Step 3 — analysis
        if emit:
            emit("[Step 3/3] Analyzing traffic for anomalies ...")

        port_counter = Counter(ports)
        ip_counter = Counter(ips)

        common_ports = {"80", "443", "53"}

        suspicious_ports = [
            (port, count)
            for port, count in port_counter.items()
            if port not in common_ports
        ]

        suspicious_ips = [
            (ip, count)
            for ip, count in ip_counter.items()
            if count > 100
        ]

        # 🌍 External detection
        internal_prefix = "10."
        external_ips = [ip for ip in ips if not ip.startswith(internal_prefix)]

        # 🧠 Build readable report
        report = []

        report.append("📊 === Analysis Summary ===")
        report.append(f"Total Packets: {len(lines)}")
        report.append(f"Unique IPs: {len(ip_counter)}")
        report.append(f"Unique Ports: {len(port_counter)}\n")

        report.append("🌐 === Top Active IPs ===")
        for ip, count in ip_counter.most_common(5):
            report.append(f"{ip} → {count} connections")

        report.append("\n🔌 === Top Ports ===")
        for port, count in port_counter.most_common(5):
            report.append(f"Port {port} → {count} times")

        report.append("\n🚨 === Suspicious Ports ===")
        if suspicious_ports:
            for port, count in suspicious_ports[:5]:
                report.append(f"⚠️ Port {port} used {count} times")
        else:
            report.append("No suspicious ports detected")

        report.append("\n🚨 === Suspicious IPs ===")
        if suspicious_ips:
            for ip, count in suspicious_ips[:5]:
                report.append(f"⚠️ {ip} → {count} connections (High Activity)")
        else:
            report.append("No suspicious IPs detected")

        report.append("\n🌍 === External Connections ===")
        report.append(f"External IPs detected: {len(set(external_ips))}")

        # 🔥 Insight
        report.append("\n🧠 === Quick Insights ===")

        if suspicious_ports:
            report.append("Possible unusual ports detected (malware or tunneling).")

        if suspicious_ips:
            report.append("High-frequency communication detected (possible beaconing or scanning).")

        if not suspicious_ports and not suspicious_ips:
            report.append("Traffic appears mostly normal.")

        analysis_output = "\n".join(report)

        results.append(StepResult(
            command="(analysis)",
            output=analysis_output,
            return_code=0,
            success=True,
        ))

        if emit:
            emit("\n===== 📊 FINAL ANALYSIS =====\n")
            emit(analysis_output)
        if emit:
            emit("TShark analysis complete.")

        return results