"""BFT — Browser Forensic ToolKit."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class BftTool(BaseTool):
    tool_id = "bft"
    name = "Browser Forensic ToolKit (BFT)"
    description = "Unified browser forensics: extract history, cookies, downloads, and saved credentials from multiple browsers."
    accepted_extensions = [".db", ".sqlite", ".json"]
    system_prerequisites = ["python3"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []

        if emit: emit("[Step 1/4] Identifying database type ...")
        results.append(self._exec(f"file '{filepath}'", emit))

        if emit: emit("[Step 2/4] Extracting all tables ...")
        results.append(self._exec(
            f"python3 -c \""
            f"import sqlite3; conn=sqlite3.connect('{filepath}'); "
            f"c=conn.cursor(); "
            f"tables=c.execute(\\\"SELECT name FROM sqlite_master WHERE type='table'\\\").fetchall(); "
            f"[print(t[0]) for t in tables]; "
            f"conn.close()\" 2>&1", emit))

        if emit: emit("[Step 3/4] Extracting history ...")
        results.append(self._exec(
            f"python3 -c \""
            f"import sqlite3; conn=sqlite3.connect('{filepath}'); "
            f"c=conn.cursor(); "
            f"[print(r) for r in c.execute(\\\"SELECT url,title FROM urls\\\").fetchall()[:30]]; "
            f"conn.close()\" 2>&1", emit))

        if emit: emit("[Step 4/4] Extracting cookies ...")
        results.append(self._exec(
            f"python3 -c \""
            f"import sqlite3; conn=sqlite3.connect('{filepath}'); "
            f"c=conn.cursor(); "
            f"[print(r) for r in c.execute(\\\"SELECT host_key,name,value FROM cookies\\\").fetchall()[:20]]; "
            f"conn.close()\" 2>&1", emit))

        if emit: emit("BFT analysis complete.")
        return results
