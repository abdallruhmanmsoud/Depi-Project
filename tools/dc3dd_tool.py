"""dc3dd — Forensic disk imaging and hashing."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class Dc3ddTool(BaseTool):
    tool_id = "dc3dd"
    name = "dc3dd Acquisition"
    description = "Forensic disk imaging with SHA256 hashing and acquisition logging."
    accepted_extensions = [".dd", ".img", ".raw", ".bin", ".e01"]
    system_prerequisites = ["dc3dd"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []
        if emit: emit(f"[Step 1/2] Identifying image ...")
        results.append(self._exec(f"file '{filepath}'", emit))
        if emit: emit("[Step 2/2] Hashing with dc3dd ...")
        results.append(self._exec(f"dc3dd if='{filepath}' hash=sha256 log=/dev/stdout 2>&1 | tail -20", emit))
        if emit: emit("dc3dd complete.")
        return results
