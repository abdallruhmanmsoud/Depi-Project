"""
╔══════════════════════════════════════════════════════════════════════════╗
║                    TOOL TEMPLATE — Copy & Edit                          ║
║                                                                          ║
║   To add your own tool to the dashboard:                                 ║
║   1. Copy this file → tools/my_tool.py                                   ║
║   2. Edit the 6 settings below (between the >>> markers)                 ║
║   3. Restart the dashboard (python app.py)                               ║
║   4. Your tool appears automatically on the dashboard!                   ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

from typing import Callable

from tools.base import BaseTool, StepResult


class MyTool(BaseTool):

    # ──────────────────────────────────────────────────────────────────────
    # >>> EDIT THESE 6 SETTINGS ONLY <<<
    # ──────────────────────────────────────────────────────────────────────

    # 1. Unique ID (used in URLs — lowercase, no spaces)
    tool_id = "my_tool"

    # 2. Display name shown on the dashboard card
    name = "My Custom Tool"

    # 3. Short description shown on the dashboard card
    description = "Describe what your tool does here."

    # 4. Absolute path to your Python script
    #    Example: "/home/nader/Depi-Project/vol_runner.py"
    script_path = "/path/to/your/script.py"

    # 5. Accepted file extensions (empty list [] = any file)
    #    Example: [".mem", ".raw", ".dmp", ".bin"]
    accepted_extensions: list[str] = []

    # 6. Extra arguments to pass to your script (optional)
    #    The uploaded file path is ALWAYS passed as the last argument.
    #    Example: ["--vol3", "vol", "--timeout", "300"]
    extra_args: list[str] = []

    # ──────────────────────────────────────────────────────────────────────
    # >>> DO NOT EDIT BELOW THIS LINE <<<
    # ──────────────────────────────────────────────────────────────────────

    system_prerequisites = ["python3"]

    def run(
        self,
        filepath: str,
        emit: Callable[[str], None] | None = None,
    ) -> list[StepResult]:
        results: list[StepResult] = []

        # Build the command: python3 <script> [extra_args...] <file>
        args_str = " ".join(f"'{a}'" for a in self.extra_args)
        cmd = f"python3 '{self.script_path}' {args_str} '{filepath}'".strip()

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
