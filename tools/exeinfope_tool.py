"""ExeinfoPE — PE file packer and protector detection."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class ExeinfoPETool(BaseTool):
    tool_id = "exeinfope"
    name = "ExeinfoPE"
    description = "Detect packers, protectors, and compilers in PE executables using signature analysis."
    accepted_extensions = [".exe", ".dll", ".sys", ".scr", ".bin"]
    system_prerequisites = ["objdump", "strings", "file"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []

        if emit: emit("[Step 1/4] File type identification ...")
        results.append(self._exec(f"file '{filepath}'", emit))

        if emit: emit("[Step 2/4] PE headers analysis ...")
        results.append(self._exec(f"objdump -f '{filepath}' 2>&1", emit))

        if emit: emit("[Step 3/4] PE sections ...")
        results.append(self._exec(f"objdump -h '{filepath}' 2>&1 | head -40", emit))

        if emit: emit("[Step 4/4] Packer signatures ...")
        results.append(self._exec(
            f"strings '{filepath}' | grep -iE 'upx|aspack|mpress|fsg|petite|themida|vmprotect' | head -20", emit))

        if emit: emit("ExeinfoPE analysis complete.")
        return results
