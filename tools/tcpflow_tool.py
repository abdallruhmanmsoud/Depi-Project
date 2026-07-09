"""tcpflow — TCP flow reconstruction and analysis."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class TcpflowTool(BaseTool):
    tool_id = "tcpflow"
    name = "tcpflow"
    description = "Reconstruct TCP flows from PCAP files to extract transferred data, files, and credentials."
    accepted_extensions = [".pcap", ".pcapng", ".cap"]
    system_prerequisites = ["tcpflow"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []
        output_dir = os.path.join(os.path.dirname(filepath), "tcpflow_out")
        os.makedirs(output_dir, exist_ok=True)

        if emit: emit("[Step 1/4] Reconstructing TCP flows ...")
        results.append(self._exec(
            f"tcpflow -r '{filepath}' -o '{output_dir}' -a 2>&1 | head -30", emit))

        if emit: emit("[Step 2/4] Listing reconstructed flows ...")
        results.append(self._exec(f"ls -lh '{output_dir}' 2>&1 | head -30", emit))

        if emit: emit("[Step 3/4] Searching for credentials ...")
        results.append(self._exec(
            f"grep -rl 'password\\|passwd\\|login\\|user' '{output_dir}' 2>&1 | head -10", emit))

        if emit: emit("[Step 4/4] HTTP content extraction ...")
        results.append(self._exec(
            f"grep -r 'HTTP\\|GET\\|POST\\|Host:' '{output_dir}' 2>&1 | head -30", emit))

        if emit: emit("tcpflow analysis complete.")
        return results
