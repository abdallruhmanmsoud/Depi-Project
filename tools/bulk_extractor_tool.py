"""bulk_extractor — Artefact carving from disk images."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class BulkExtractorTool(BaseTool):
    tool_id = "bulk_extractor"
    name = "Bulk Extractor"
    description = "Carve artefacts (emails, URLs, credit cards, domains) from disk images."
    accepted_extensions = [".dd", ".img", ".raw", ".bin", ".e01"]
    system_prerequisites = ["bulk_extractor"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []
        output_dir = os.path.join(os.path.dirname(filepath), "bulk_out")
        os.makedirs(output_dir, exist_ok=True)
        if emit: emit(f"[Step 1/2] Starting bulk_extractor carving ...")
        if emit: emit(f"  Output directory: {output_dir}")
        results.append(self._exec(f"bulk_extractor -o '{output_dir}' '{filepath}' 2>&1 | tail -30", emit))
        if emit: emit("[Step 2/2] Listing carved artefacts ...")
        results.append(self._exec(f"ls -lh '{output_dir}' 2>&1", emit))
        if emit: emit(f"Bulk extraction complete. Output: {output_dir}")
        return results
