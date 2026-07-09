"""
Base class for all forensic analysis tool modules.

To create a new tool, subclass ``BaseTool`` and override the required
class attributes and the ``run`` method.  Drop the file into the
``tools/`` directory and the dashboard will discover it automatically.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable

logger = logging.getLogger(__name__)


@dataclass
class StepResult:
    """Result of a single analysis step."""
    command: str
    output: str
    return_code: int
    success: bool


class BaseTool:
    """Abstract base for every pluggable analysis tool.

    Subclasses **must** set the following class‑level attributes:

    * ``tool_id``   – short slug used in URLs and filenames (e.g. ``"strings"``).
    * ``name``      – human‑readable name shown in the dashboard.
    * ``description`` – one‑liner shown in the dashboard card.
    * ``accepted_extensions`` – list of file extensions the tool works with
      (e.g. ``[".bin", ".dmp", ".raw"]``).  An empty list means *any* file.
    * ``system_prerequisites`` – list of command‑line programs that must be
      available on ``$PATH`` (e.g. ``["strings", "file"]``).
    """

    tool_id: str = ""
    name: str = ""
    description: str = ""
    accepted_extensions: list[str] = []
    system_prerequisites: list[str] = []

    # ------------------------------------------------------------------
    # Prerequisite checking
    # ------------------------------------------------------------------

    @classmethod
    def check_prerequisites(cls) -> list[dict]:
        """Return a list of dicts ``{"program": ..., "installed": bool}``."""
        results = []
        for prog in cls.system_prerequisites:
            found = shutil.which(prog) is not None
            results.append({"program": prog, "installed": found})
        return results

    @classmethod
    def all_prerequisites_met(cls) -> bool:
        return all(r["installed"] for r in cls.check_prerequisites())

    # ------------------------------------------------------------------
    # Execution helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _exec(
        command: str,
        emit: Callable[[str], None] | None = None,
    ) -> StepResult:
        """Run a shell command, stream output line‑by‑line via *emit*,
        and return a ``StepResult``.
        """
        if emit:
            emit(f"$ {command}")
        logger.info("Executing: %s", command)

        lines: list[str] = []
        try:
            proc = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                stripped = line.rstrip("\n")
                lines.append(stripped)
                if emit:
                    emit(stripped)
            proc.wait()
            rc = proc.returncode
        except Exception as exc:
            msg = f"Error running command: {exc}"
            lines.append(msg)
            if emit:
                emit(msg)
            rc = -1

        return StepResult(
            command=command,
            output="\n".join(lines),
            return_code=rc,
            success=(rc == 0),
        )

    # ------------------------------------------------------------------
    # Main entry point — override in subclass
    # ------------------------------------------------------------------

    def run(
        self,
        filepath: str,
        emit: Callable[[str], None] | None = None,
    ) -> list[StepResult]:
        """Execute the analysis on *filepath*.

        *emit* is an optional callback that receives individual log lines
        so the dashboard can stream them to the browser in real time.

        Returns a list of ``StepResult`` objects (one per step).
        """
        raise NotImplementedError("Subclasses must implement run()")
