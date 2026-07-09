"""The Sleuth Kit — Deep file system analysis using istat, mmls, ils."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class TskTool(BaseTool):
    tool_id = "tsk"
    name = "The Sleuth Kit (TSK)"
    description = "Deep file system analysis: partition layout (mmls), inode details (istat), deleted files (ils)."
    accepted_extensions = [".dd", ".img", ".raw", ".bin", ".e01"]
    system_prerequisites = ["mmls", "istat", "ils"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []

        if emit: emit("[Step 1/4] Reading partition layout (mmls) ...")
        results.append(self._exec(f"mmls '{filepath}' 2>&1", emit))

        if emit: emit("[Step 2/4] File system statistics (fsstat) ...")
        results.append(self._exec(f"fsstat '{filepath}' 2>&1 | head -50", emit))

        if emit: emit("[Step 3/4] Listing deleted files (ils) ...")
        results.append(self._exec(f"ils '{filepath}' 2>&1 | head -50", emit))

        if emit: emit("[Step 4/4] Full file listing (fls) ...")
        results.append(self._exec(f"fls -r '{filepath}' 2>&1 | head -100", emit))

        if emit: emit("TSK analysis complete.")
        return results
