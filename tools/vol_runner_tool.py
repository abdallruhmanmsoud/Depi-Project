"""
Volatility Plugin Runner integration module.
Wraps the user's vol_runner.py script to run all Volatility plugins
against a memory dump and produce a JSON results file.

Setup:
  1. Place vol_runner.py in the project root (or set VOL_RUNNER_SCRIPT).
  2. Ensure 'vol3' (Volatility 3) is on PATH.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Callable

from tools.base import BaseTool, StepResult

# Path to vol_runner.py — admin can override via env var
_DEFAULT_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "vol_runner.py",
)
VOL_RUNNER_SCRIPT = os.environ.get("VOL_RUNNER_SCRIPT", _DEFAULT_SCRIPT)


def _find_vol3_binary() -> str | None:
    """
    Locate a **Volatility 3** binary on PATH.

    Search order: vol3, volatility3, vol.
    Each candidate is verified by running ``<binary> -h`` and checking
    that stdout contains ``"Volatility 3 Framework"``.  This rejects
    Volatility 2 (a Python 2 script that crashes on Python 3 with a
    SyntaxError on ``print "\\n"``).

    Never returns a path to Volatility 2.
    """
    for name in ("vol3", "volatility3", "vol"):
        path = shutil.which(name)
        if path is None:
            continue
        try:
            result = subprocess.run(
                [path, "-h"],
                capture_output=True, text=True, timeout=15,
            )
            if "Volatility 3 Framework" in (result.stdout or ""):
                return path
        except Exception:
            continue
    return None


class VolRunnerTool(BaseTool):
    tool_id = "vol_runner"
    name = "Volatility Plugin Runner"
    description = (
        "Run all Volatility 3 plugins against a memory dump using "
        "vol_runner.py. Produces per-plugin text output and a unified "
        "results.json file with full forensic data."
    )
    accepted_extensions = [".raw", ".dmp", ".mem", ".vmem", ".img", ".bin"]
    system_prerequisites = ["python3"]

    @classmethod
    def check_prerequisites(cls) -> list[dict]:
        """Check for python3, a Volatility 3 binary, and vol_runner.py."""
        results = super().check_prerequisites()

        # Check for vol3 binary (verified as Volatility 3)
        vol_bin = _find_vol3_binary()
        results.append({
            "program": "Volatility 3 (vol3 / volatility3)",
            "installed": vol_bin is not None,
        })

        # Check for vol_runner.py script
        results.append({
            "program": f"vol_runner.py ({VOL_RUNNER_SCRIPT})",
            "installed": os.path.isfile(VOL_RUNNER_SCRIPT),
        })

        return results

    def run(
        self,
        filepath: str,
        emit: Callable[[str], None] | None = None,
    ) -> list[StepResult]:
        results: list[StepResult] = []

        # Step 1 — verify vol_runner.py exists
        if emit:
            emit("[Step 1/4] Checking for vol_runner.py ...")
        if not os.path.isfile(VOL_RUNNER_SCRIPT):
            msg = (
                f"vol_runner.py not found at: {VOL_RUNNER_SCRIPT}\n"
                "Place vol_runner.py in the project root directory or set "
                "the VOL_RUNNER_SCRIPT environment variable."
            )
            if emit:
                emit(f"  ERROR: {msg}")
            results.append(StepResult(
                command="(check vol_runner.py)",
                output=msg,
                return_code=1,
                success=False,
            ))
            return results

        if emit:
            emit(f"  Found: {VOL_RUNNER_SCRIPT}")
        results.append(StepResult(
            command="(check vol_runner.py)",
            output=f"Found: {VOL_RUNNER_SCRIPT}",
            return_code=0,
            success=True,
        ))

        # Step 2 — find Volatility 3 binary (verified, never Volatility 2)
        if emit:
            emit("[Step 2/4] Locating Volatility 3 binary ...")
        vol_bin = _find_vol3_binary()
        if not vol_bin:
            msg = (
                "No Volatility 3 binary found on PATH.\n"
                "Searched for: vol3, volatility3, vol  "
                "(each verified for 'Volatility 3 Framework' in -h output).\n"
                "Install Volatility 3: pip install volatility3"
            )
            if emit:
                emit(f"  ERROR: {msg}")
            results.append(StepResult(
                command="(find volatility3)",
                output=msg,
                return_code=1,
                success=False,
            ))
            return results

        if emit:
            emit(f"  Found Volatility 3: {vol_bin}")
        results.append(StepResult(
            command="(find volatility3)",
            output=f"Found Volatility 3: {vol_bin}",
            return_code=0,
            success=True,
        ))

        # Step 3 — build output directory
        if emit:
            emit("[Step 3/4] Preparing output directory ...")
        basename = os.path.splitext(os.path.basename(filepath))[0]
        output_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "reports",
            f"{basename}_vol_runner",
        )
        os.makedirs(output_dir, exist_ok=True)
        if emit:
            emit(f"  Output directory: {output_dir}")
        results.append(StepResult(
            command="(prepare output dir)",
            output=f"Output directory: {output_dir}",
            return_code=0,
            success=True,
        ))

        # Step 4 — run vol_runner.py with --vol3 pointing to the VERIFIED binary
        if emit:
            emit("[Step 4/4] Running vol_runner.py (this may take a while) ...")
        cmd = (
            f"python3 '{VOL_RUNNER_SCRIPT}' "
            f"-f '{filepath}' "
            f"--vol3 '{vol_bin}' "
            f"-o '{output_dir}'"
        )
        step = self._exec(cmd, emit)
        results.append(step)

        # Show location of results.json if it was created
        results_json = os.path.join(output_dir, "results.json")
        if os.path.isfile(results_json):
            if emit:
                emit(f"Results JSON: {results_json}")
        else:
            if emit:
                emit("WARNING: results.json was not created. Check the output above for errors.")

        if emit:
            emit("vol_runner.py execution complete.")
        return results
