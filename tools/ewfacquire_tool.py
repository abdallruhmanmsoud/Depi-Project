"""ewfacquire — Forensic image acquisition in EWF/E01 format."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class EwfacquireTool(BaseTool):
    tool_id = "ewfacquire"
    name = "ewfacquire (EWF Acquisition)"
    description = "Acquire forensic images in EWF/E01 format with hashing and metadata."
    accepted_extensions = [".dd", ".img", ".raw", ".bin"]
    system_prerequisites = ["ewfacquire", "ewfinfo"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []
        basename = os.path.splitext(os.path.basename(filepath))[0]
        output = os.path.join(os.path.dirname(filepath), basename + "_ewf")

        if emit: emit("[Step 1/3] Identifying file ...")
        results.append(self._exec(f"file '{filepath}'", emit))

        if emit: emit("[Step 2/3] Acquiring image in EWF format ...")
        results.append(self._exec(
            f"ewfacquire -u -t '{output}' -d sha256 '{filepath}' 2>&1", emit))

        if emit: emit("[Step 3/3] Verifying EWF image info ...")
        results.append(self._exec(f"ewfinfo '{output}.E01' 2>&1", emit))

        if emit: emit("ewfacquire complete.")
        return results
