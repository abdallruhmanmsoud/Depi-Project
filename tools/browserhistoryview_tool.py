"""BrowserHistoryView — Extract and analyse browser history."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class BrowserHistoryViewTool(BaseTool):
    tool_id = "browserhistoryview"
    name = "BrowserHistoryView"
    description = "Extract and analyse browser history from Chrome, Firefox, and Edge SQLite databases."
    accepted_extensions = [".db", ".sqlite"]
    system_prerequisites = ["python3"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []

        if emit: emit("[Step 1/3] Identifying browser database ...")
        results.append(self._exec(f"file '{filepath}'", emit))

        if emit: emit("[Step 2/3] Extracting browsing history ...")
        results.append(self._exec(
            f"python3 -c \""
            f"import sqlite3; conn=sqlite3.connect('{filepath}'); "
            f"c=conn.cursor(); "
            f"[print(r) for r in c.execute(\\\"SELECT url,title,visit_count FROM urls ORDER BY visit_count DESC\\\").fetchall()[:30]]; "
            f"conn.close()\" 2>&1", emit))

        if emit: emit("[Step 3/3] Extracting downloads history ...")
        results.append(self._exec(
            f"python3 -c \""
            f"import sqlite3; conn=sqlite3.connect('{filepath}'); "
            f"c=conn.cursor(); "
            f"[print(r) for r in c.execute(\\\"SELECT target_path,tab_url FROM downloads\\\").fetchall()[:20]]; "
            f"conn.close()\" 2>&1", emit))

        if emit: emit("BrowserHistoryView analysis complete.")
        return results
