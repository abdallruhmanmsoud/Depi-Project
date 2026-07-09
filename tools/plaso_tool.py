"""Plaso — Super timeline generation from forensic artefacts."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

LOG2TIMELINE = "/home/depi/DEPI_Project/.venv/bin/log2timeline"
PSORT = "/home/depi/DEPI_Project/.venv/bin/psort"

class PlasoTool(BaseTool):
    tool_id = "plaso"
    name = "Plaso (log2timeline)"
    description = "Generate a super timeline from disk images and forensic artefacts using Plaso/log2timeline."
    accepted_extensions = [".dd", ".img", ".raw", ".bin", ".e01"]
    system_prerequisites = ["log2timeline.py", "psort.py"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []
        basename = os.path.splitext(os.path.basename(filepath))[0]
        plaso_file = f"/tmp/{basename}.plaso"
        timeline_csv = f"/tmp/{basename}_timeline.csv"

        if os.path.exists(plaso_file): os.remove(plaso_file)
        if os.path.exists(timeline_csv): os.remove(timeline_csv)

        if emit: emit("[Step 1/3] Running log2timeline ...")
        results.append(self._exec(
            f"'{LOG2TIMELINE}' --storage_file '{plaso_file}' '{filepath}' 2>&1 | tail -5", emit))

        if emit: emit("[Step 2/3] Sorting timeline with psort ...")
        results.append(self._exec(
            f"'{PSORT}' '{plaso_file}' -o l2tcsv -w '{timeline_csv}' 2>&1 | tail -5", emit))

        if emit: emit("[Step 3/3] Timeline summary ...")
        results.append(self._exec(f"head -20 '{timeline_csv}' 2>&1", emit))

        if emit: emit("Plaso timeline complete.")
        return results
