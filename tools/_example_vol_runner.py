"""
╔══════════════════════════════════════════════════════════════════════════╗
║            EXAMPLE: vol_runner.py Integration                            ║
║                                                                          ║
║   To use this:                                                           ║
║   1. Copy this file → tools/my_vol_runner.py  (remove the _ prefix)      ║
║   2. Edit script_path to point to YOUR vol_runner.py                     ║
║   3. Restart the dashboard                                               ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

from typing import Callable

from tools.base import BaseTool, StepResult


class MyVolRunner(BaseTool):

    # >>> EDIT THESE <<<

    tool_id = "my_vol_runner"
    name = "My Vol Runner"
    description = "Run vol_runner.py against a memory dump with all Volatility plugins."

    # Point this to YOUR vol_runner.py
    script_path = "/home/nader/Depi-Project/vol_runner.py"

    accepted_extensions = [".mem", ".raw", ".dmp", ".vmem", ".img", ".bin"]

    # Extra arguments passed BEFORE the file path.
    # vol_runner.py expects: -f <file> --vol3 <vol_binary>
    # Change "vol" to your Volatility binary name/path if different.
    extra_args = ["--vol3", "vol"]

    # >>> DO NOT EDIT BELOW <<<

    system_prerequisites = ["python3"]

    def run(
        self,
        filepath: str,
        emit: Callable[[str], None] | None = None,
    ) -> list[StepResult]:
        results: list[StepResult] = []

        # vol_runner.py uses -f for the file, not as last argument
        args_str = " ".join(f"'{a}'" for a in self.extra_args)
        cmd = f"python3 '{self.script_path}' -f '{filepath}' {args_str}".strip()

        if emit:
            emit(f"Running: {self.name}")
            emit(f"Script : {self.script_path}")
            emit(f"File   : {filepath}")
            emit("")

        step = self._exec(cmd, emit)
        results.append(step)

        if emit:
            if step.success:
                emit("")
                emit("Analysis complete.")
            else:
                emit("")
                emit(f"Script exited with code {step.return_code}. Check output above.")

        return results
