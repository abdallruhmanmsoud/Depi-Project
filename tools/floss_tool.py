"""FLOSS — FireEye Labs Obfuscated String Solver."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class FlossTool(BaseTool):
    tool_id = "floss"
    name = "FLOSS (String Extractor)"
    description = "Extract obfuscated strings from malware samples including stack strings and encoded blobs."
    accepted_extensions = [".exe", ".dll", ".sys", ".bin", ".scr"]
    system_prerequisites = ["strings"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []

        if emit: emit("[Step 1/4] Extracting ASCII strings ...")
        results.append(self._exec(f"strings -a -n 4 '{filepath}' | head -200", emit))

        if emit: emit("[Step 2/4] Extracting Unicode strings ...")
        results.append(self._exec(f"strings -a -e l -n 4 '{filepath}' | head -100", emit))

        if emit: emit("[Step 3/4] Detecting obfuscated patterns ...")
        results.append(self._exec(f"strings -a -n 4 '{filepath}' | grep -iE 'base64|xor|rot|encode|decrypt|payload' | head -30", emit))

        if emit: emit("[Step 4/4] String statistics ...")
        results.append(self._exec(f"strings -a -n 4 '{filepath}' | wc -l", emit))

        if emit: emit("FLOSS analysis complete.")
        return results
