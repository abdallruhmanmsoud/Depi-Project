"""pestudio-cli — PE file static analysis."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class PestudioTool(BaseTool):
    tool_id = "pestudio"
    name = "pestudio-cli"
    description = "Static PE file analysis: headers, imports, exports, strings, and indicators of compromise."
    accepted_extensions = [".exe", ".dll", ".sys", ".bin", ".scr"]
    system_prerequisites = ["objdump", "strings", "readelf"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []

        if emit: emit("[Step 1/4] File type identification ...")
        results.append(self._exec(f"file '{filepath}'", emit))

        if emit: emit("[Step 2/4] PE headers analysis ...")
        results.append(self._exec(f"objdump -f '{filepath}' 2>&1", emit))

        if emit: emit("[Step 3/4] Import table ...")
        results.append(self._exec(f"objdump -p '{filepath}' 2>&1 | grep -A 100 'Import' | head -50", emit))

        if emit: emit("[Step 4/4] Suspicious strings ...")
        results.append(self._exec(f"strings '{filepath}' | grep -iE 'cmd|powershell|http|reg|hack|inject|shell' | head -30", emit))

        if emit: emit("pestudio analysis complete.")
        return results
