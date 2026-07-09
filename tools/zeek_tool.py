"""Zeek — Network traffic analysis and log generation."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class ZeekTool(BaseTool):
    tool_id = "zeek"
    name = "Zeek (Network Analysis)"
    description = "Analyse PCAP files with Zeek to generate structured logs: DNS, HTTP, SSL, files, and connections."
    accepted_extensions = [".pcap", ".pcapng", ".cap"]
    system_prerequisites = ["zeek"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []
        output_dir = os.path.join(os.path.dirname(filepath), "zeek_logs")
        os.makedirs(output_dir, exist_ok=True)

        if emit: emit("[Step 1/3] Running Zeek on PCAP ...")
        results.append(self._exec(
            f"cd '{output_dir}' && zeek -r '{filepath}' 2>&1", emit))

        if emit: emit("[Step 2/3] Listing generated logs ...")
        results.append(self._exec(f"ls -lh '{output_dir}' 2>&1", emit))

        if emit: emit("[Step 3/3] Showing connection summary ...")
        results.append(self._exec(
            f"cat '{output_dir}/conn.log' 2>&1 | head -30", emit))

        if emit: emit("Zeek analysis complete.")
        return results
