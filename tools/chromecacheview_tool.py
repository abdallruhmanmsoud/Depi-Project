"""ChromeCacheView — Chrome cache analysis."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class ChromeCacheViewTool(BaseTool):
    tool_id = "chromecacheview"
    name = "ChromeCacheView"
    description = "Analyse Chrome cache files to extract cached URLs, content types, and timestamps."
    accepted_extensions = [".db", ".sqlite", ".json"]
    system_prerequisites = ["python3"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []

        if emit: emit("[Step 1/3] Reading cache database ...")
        results.append(self._exec(f"file '{filepath}'", emit))

        if emit: emit("[Step 2/3] Extracting cached URLs ...")
        results.append(self._exec(
            f"python3 -c \""
            f"import sqlite3; conn=sqlite3.connect('{filepath}'); "
            f"c=conn.cursor(); "
            f"[print(r) for r in c.execute(\\\"SELECT url,mime_type FROM entries\\\").fetchall()[:30]]; "
            f"conn.close()\" 2>&1 | head -30", emit))

        if emit: emit("[Step 3/3] Listing strings from cache ...")
        results.append(self._exec(f"strings '{filepath}' | grep -E 'http|https' | head -30", emit))

        if emit: emit("ChromeCacheView analysis complete.")
        return results
