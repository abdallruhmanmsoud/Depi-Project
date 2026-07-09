"""
Strings analysis module.
Extracts printable strings from binary files using the ``strings`` command.
"""

from __future__ import annotations

import os
from typing import Callable

from tools.base import BaseTool, StepResult


class StringsTool(BaseTool):
    tool_id = "strings"
    name = "Strings Extraction"
    description = (
        "Extract printable ASCII and Unicode strings from binary files. "
        "Useful for quick triage of executables, memory dumps, and firmware images."
    )
    accepted_extensions: list[str] = []  # accepts any file
    system_prerequisites = ["strings", "file"]

    def run(
        self,
        filepath: str,
        emit: Callable[[str], None] | None = None,
    ) -> list[StepResult]:
        results: list[StepResult] = []
        basename = os.path.basename(filepath)

        # Step 1 — identify file type
        if emit:
            emit(f"[Step 1/4] Identifying file type for {basename} ...")
        step = self._exec(f"file '{filepath}'", emit)
        results.append(step)

        # Step 2 — extract ASCII strings (min length 4)
        if emit:
            emit("[Step 2/4] Extracting ASCII strings (min length 4) ...")
        step = self._exec(f"strings -a -n 4 '{filepath}' | head -500", emit)
        results.append(step)

        # Step 3 — extract Unicode (16‑bit LE) strings
        if emit:
            emit("[Step 3/4] Extracting Unicode strings ...")
        step = self._exec(f"strings -a -e l -n 4 '{filepath}' | head -500", emit)
        results.append(step)

        # Step 4 — summary statistics
        if emit:
            emit("[Step 4/4] Counting total strings found ...")
        step = self._exec(f"strings -a -n 4 '{filepath}' | wc -l", emit)
        results.append(step)

        if emit:
            emit("Strings extraction complete.")
        return results
