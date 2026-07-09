"""mysqlbinlog — MySQL binary log analysis and timeline reconstruction."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class MysqlbinlogTool(BaseTool):
    tool_id = "mysqlbinlog"
    name = "mysqlbinlog"
    description = "Parse MySQL binary logs to reconstruct DML/DDL timeline and detect suspicious database operations."
    accepted_extensions = [".bin", ".log", ".000001", ".000002", ".000003"]
    system_prerequisites = ["mysqlbinlog"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []

        if emit: emit("[Step 1/3] Parsing binary log header ...")
        results.append(self._exec(f"mysqlbinlog --short-form '{filepath}' 2>&1 | head -50", emit))

        if emit: emit("[Step 2/3] Extracting DML/DDL timeline ...")
        results.append(self._exec(f"mysqlbinlog '{filepath}' 2>&1 | grep -E 'INSERT|UPDATE|DELETE|CREATE|DROP|ALTER' | head -50", emit))

        if emit: emit("[Step 3/3] Checking for suspicious bulk operations ...")
        results.append(self._exec(f"mysqlbinlog '{filepath}' 2>&1 | grep -c 'DELETE' && echo 'DELETE operations found'", emit))

        if emit: emit("mysqlbinlog analysis complete.")
        return results
