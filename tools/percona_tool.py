"""Percona Toolkit — MySQL query analysis and diagnostics."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class PerconaTool(BaseTool):
    tool_id = "percona"
    name = "Percona Toolkit"
    description = "Analyse MySQL slow query logs and binary logs using Percona pt-query-digest."
    accepted_extensions = [".log", ".bin", ".slow"]
    system_prerequisites = ["pt-query-digest"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []

        if emit: emit("[Step 1/2] Running pt-query-digest ...")
        results.append(self._exec(f"pt-query-digest '{filepath}' 2>&1 | head -80", emit))

        if emit: emit("[Step 2/2] Top queries summary ...")
        results.append(self._exec(f"pt-query-digest --report-format=query_report '{filepath}' 2>&1 | head -50", emit))

        if emit: emit("Percona analysis complete.")
        return results
