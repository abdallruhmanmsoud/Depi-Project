"""
YARA scanning module.
Scans files against YARA rule sets.
"""

from __future__ import annotations

import os
from typing import Callable

from tools.base import BaseTool, StepResult

# Default YARA rules directory (admin can change)
DEFAULT_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "yara_rules",
)


class YaraTool(BaseTool):
    tool_id = "yara"
    name = "YARA Scanner"
    description = (
        "Scan files with YARA rules for malware signatures and IOC patterns. "
        "Place .yar/.yara rule files in the yara_rules/ directory."
    )
    accepted_extensions: list[str] = []  # accepts any file
    system_prerequisites = ["yara"]

    def run(
        self,
        filepath: str,
        emit: Callable[[str], None] | None = None,
    ) -> list[StepResult]:
        results: list[StepResult] = []
        basename = os.path.basename(filepath)
        rules_dir = DEFAULT_RULES_DIR

        # Step 1 — check for YARA rules directory
        if emit:
            emit(f"[Step 1/3] Checking for YARA rules in {rules_dir} ...")

        if not os.path.isdir(rules_dir):
            os.makedirs(rules_dir, exist_ok=True)
            if emit:
                emit(
                    f"  Created empty rules directory: {rules_dir}\n"
                    "  Please add .yar or .yara rule files to this directory."
                )

        rule_files = [
            f for f in os.listdir(rules_dir)
            if f.endswith((".yar", ".yara"))
        ]
        if not rule_files:
            msg = (
                "No YARA rule files found. "
                f"Add .yar/.yara files to {rules_dir} and re‑run."
            )
            if emit:
                emit(f"  WARNING: {msg}")
            results.append(StepResult(
                command="(check rules directory)",
                output=msg,
                return_code=1,
                success=False,
            ))
            return results

        if emit:
            emit(f"  Found {len(rule_files)} rule file(s): {', '.join(rule_files)}")
        results.append(StepResult(
            command="(check rules directory)",
            output=f"Found {len(rule_files)} rule file(s)",
            return_code=0,
            success=True,
        ))

        # Step 2 — validate YARA installation
        if emit:
            emit("[Step 2/3] Checking YARA version ...")
        step = self._exec("yara --version", emit)
        results.append(step)

        # Step 3 — scan with each rule file
        if emit:
            emit(f"[Step 3/3] Scanning {basename} with YARA rules ...")
        for rule_file in rule_files:
            rule_path = os.path.join(rules_dir, rule_file)
            if emit:
                emit(f"  Scanning with {rule_file} ...")
            step = self._exec(f"yara '{rule_path}' '{filepath}'", emit)
            results.append(step)

        if emit:
            emit("YARA scan complete.")
        return results
