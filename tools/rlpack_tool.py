"""RLPack — PE unpacker and decompressor."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class RLPackTool(BaseTool):
    tool_id = "rlpack"
    name = "RLPack (Unpacker)"
    description = "Unpack and decompress packed PE executables using UPX and other decompression techniques."
    accepted_extensions = [".exe", ".dll", ".sys", ".scr", ".bin"]
    system_prerequisites = ["upx", "strings"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []
        output_dir = os.path.join(os.path.dirname(filepath), "unpacked")
        os.makedirs(output_dir, exist_ok=True)
        unpacked = os.path.join(output_dir, os.path.basename(filepath))

        if emit: emit("[Step 1/4] Testing if file is packed ...")
        results.append(self._exec(f"upx -t '{filepath}' 2>&1", emit))

        if emit: emit("[Step 2/4] Attempting to unpack ...")
        import shutil
        shutil.copy2(filepath, unpacked)
        results.append(self._exec(f"upx -d '{unpacked}' 2>&1", emit))

        if emit: emit("[Step 3/4] Strings from unpacked file ...")
        results.append(self._exec(f"strings '{unpacked}' | head -100", emit))

        if emit: emit("[Step 4/4] Comparing file sizes ...")
        results.append(self._exec(f"ls -lh '{filepath}' '{unpacked}' 2>&1", emit))

        if emit: emit("RLPack unpacking complete.")
        return results
