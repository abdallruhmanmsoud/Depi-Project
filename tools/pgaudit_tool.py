"""pgAudit — PostgreSQL audit log analysis."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class PgAuditTool(BaseTool):
    tool_id = "pgaudit"
    name = "pgAudit"
    description = "Parse and analyse PostgreSQL audit logs to detect unauthorized access, data tampering, and suspicious queries."
    accepted_extensions = [".log", ".csv", ".txt"]
    system_prerequisites = ["psql"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []
        if emit: emit("[Step 1/4] Reading audit log ...")
        results.append(self._exec(f"head -50 '{filepath}'", emit))
        if emit: emit("[Step 2/4] Filtering AUDIT events ...")
        results.append(self._exec(f"grep -i 'AUDIT' '{filepath}' | head -50", emit))
        if emit: emit("[Step 3/4] Detecting suspicious operations ...")
        results.append(self._exec(f"grep -iE 'DROP|TRUNCATE|DELETE|ALTER' '{filepath}' | head -30", emit))
        if emit: emit("[Step 4/4] Timeline reconstruction ...")
        results.append(self._exec(f"grep -oP '\d{{4}}-\d{{2}}-\d{{2}}' '{filepath}' | sort | uniq -c | head -20", emit))
        if emit: emit("pgAudit analysis complete.")
        return results
