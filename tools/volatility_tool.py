"""
Volatility 3 memory analysis module.
Runs common Volatility plugins against memory dump files.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Callable

from tools.base import BaseTool, StepResult


def _find_vol3_binary() -> str | None:
    """
    Locate a Volatility **3** binary on PATH.

    Search order: vol3, volatility3, vol.
    Each candidate is verified by running ``<binary> -h`` and checking
    that stdout contains ``"Volatility 3 Framework"``.  This prevents
    accidentally selecting Volatility 2 (which is a Python 2 script
    and will crash on Python 3).
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


# Resolve once at import time; run() will re-check if this is None.
VOL3 = _find_vol3_binary()


class VolatilityTool(BaseTool):
    tool_id = "volatility"
    name = "Volatility 3 Memory Analysis"
    description = (
        "Analyze memory dumps with Volatility 3 framework. "
        "Runs common plugins such as pslist, pstree, netscan, and cmdline."
    )
    accepted_extensions = [".raw", ".dmp", ".mem", ".vmem", ".img", ".bin"]
    system_prerequisites = ["vol3", "python3"]

    # Plugins to run (admin can extend)
    DEFAULT_PLUGINS = [
        "windows.info",
        "windows.pslist",
        "windows.pstree",
        "windows.netscan",
        "windows.cmdline",
    ]

    def run(
        self,
        filepath: str,
        emit: Callable[[str], None] | None = None,
    ) -> list[StepResult]:
        results: list[StepResult] = []
        plugins = self.DEFAULT_PLUGINS
        total = len(plugins) + 1  # +1 for the verification step

        # Step 1 — verify Volatility 3 installation
        if emit:
            emit(f"[Step 1/{total}] Verifying Volatility 3 installation ...")

        vol_bin = VOL3 or _find_vol3_binary()
        if not vol_bin:
            msg = (
                "ERROR: Volatility 3 not found on PATH.\n"
                "Searched for: vol3, volatility3, vol  "
                "(each verified for 'Volatility 3 Framework' in -h output).\n"
                "Install with: pip install volatility3"
            )
            if emit:
                emit(msg)
            results.append(StepResult(
                command="(find volatility3)",
                output=msg,
                return_code=1,
                success=False,
            ))
            return results

        # Show version header
        step = self._exec(f"'{vol_bin}' -h | head -5", emit)
        results.append(step)
        if emit:
            emit(f"  Using: {vol_bin}")

        # Steps 2..N — run each plugin
        for idx, plugin in enumerate(plugins, start=2):
            if emit:
                emit(f"[Step {idx}/{total}] Running plugin: {plugin} ...")
            cmd = f"'{vol_bin}' -f '{filepath}' {plugin}"
            step = self._exec(cmd, emit)
            results.append(step)
            if not step.success and emit:
                emit(f"  Plugin {plugin} returned non-zero — this may be "
                     "expected if the dump is not a Windows image.")

        if emit:
            emit("Volatility analysis complete.")
        return results
