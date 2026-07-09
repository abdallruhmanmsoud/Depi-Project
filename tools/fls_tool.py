"""fls — File system enumeration using The Sleuth Kit."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class FlsTool(BaseTool):
    tool_id = "fls"
    name = "FLS (Sleuth Kit)"
    description = "Enumerate files and directories from disk images using The Sleuth Kit fls/fsstat."
    accepted_extensions = [".dd", ".img", ".raw", ".bin", ".e01"]
    system_prerequisites = ["fls", "fsstat"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []
        if emit: emit("[Step 1/3] Reading file system info ...")
        results.append(self._exec(f"fsstat '{filepath}' 2>&1 | head -40", emit))
        if emit: emit("[Step 2/3] Listing all files (fls) ...")
        results.append(self._exec(f"fls -r '{filepath}' 2>&1 | head -100", emit))
        if emit: emit("[Step 3/3] Listing deleted files ...")
        results.append(self._exec(f"fls -r -d '{filepath}' 2>&1 | head -50", emit))
        if emit: emit("FLS analysis complete.")
        return results
