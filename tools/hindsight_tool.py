"""Hindsight — Chrome/Chromium browser artefact analysis."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class HindsightTool(BaseTool):
    tool_id = "hindsight"
    name = "Hindsight (Chrome Forensics)"
    description = "Analyse Chrome/Chromium browser artefacts: history, downloads, cookies, cache, and timeline."
    accepted_extensions = [".db", ".sqlite", ".json"]
    system_prerequisites = ["python3"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []

        if emit: emit("[Step 1/4] Identifying Chrome database ...")
        results.append(self._exec(f"file '{filepath}'", emit))

        if emit: emit("[Step 2/4] Extracting browsing timeline ...")
        results.append(self._exec(
            f"python3 -c \"import sqlite3; conn=sqlite3.connect('{filepath}'); c=conn.cursor(); [print(r) for r in c.execute('SELECT url,title,visit_count FROM urls ORDER BY visit_count DESC').fetchall()[:20]]; conn.close()\" 2>&1", emit))

        if emit: emit("[Step 3/4] Extracting downloads ...")
        results.append(self._exec(
            f"python3 -c \"import sqlite3; conn=sqlite3.connect('{filepath}'); c=conn.cursor(); [print(r) for r in c.execute('SELECT target_path,tab_url FROM downloads').fetchall()[:20]]; conn.close()\" 2>&1", emit))

        if emit: emit("[Step 4/4] Extracting cookies ...")
        results.append(self._exec(
            f"python3 -c \"import sqlite3; conn=sqlite3.connect('{filepath}'); c=conn.cursor(); [print(r) for r in c.execute('SELECT host_key,name,value FROM cookies').fetchall()[:20]]; conn.close()\" 2>&1", emit))

        if emit: emit("Hindsight analysis complete.")
        return results
