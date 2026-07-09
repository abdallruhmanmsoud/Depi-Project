"""WebBrowserPassView — Extract saved browser passwords."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class BrowserPwdViewTool(BaseTool):
    tool_id = "browserpwdview"
    name = "WebBrowserPassView"
    description = "Extract saved passwords from Chrome, Firefox, Edge, and IE browser profiles."
    accepted_extensions = [".db", ".sqlite", ".json"]
    system_prerequisites = ["python3"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []

        if emit: emit("[Step 1/2] Extracting saved passwords from browser DB ...")
        results.append(self._exec(
            f"python3 -c \""
            f"import sqlite3; conn=sqlite3.connect('{filepath}'); "
            f"c=conn.cursor(); "
            f"[print(r) for r in c.execute(\\\"SELECT origin_url,username_value FROM logins\\\").fetchall()]; "
            f"conn.close()\" 2>&1 | head -30", emit))

        if emit: emit("[Step 2/2] Checking for cookie data ...")
        results.append(self._exec(
            f"python3 -c \""
            f"import sqlite3; conn=sqlite3.connect('{filepath}'); "
            f"c=conn.cursor(); "
            f"[print(r) for r in c.execute(\\\"SELECT host_key,name FROM cookies\\\").fetchall()[:20]]; "
            f"conn.close()\" 2>&1 | head -30", emit))

        if emit: emit("WebBrowserPassView analysis complete.")
        return results
