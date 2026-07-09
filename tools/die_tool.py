"""DIE — Detect It Easy, packer and compiler detection."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class DieTool(BaseTool):
    tool_id = "die"
    name = "DIE (Detect It Easy)"
    description = "Detect packers, compilers, and protectors in PE files using signature-based detection."
    accepted_extensions = [".exe", ".dll", ".sys", ".bin", ".scr"]
    system_prerequisites = ["strings", "objdump"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []

        if emit: emit("[Step 1/4] File identification ...")
        results.append(self._exec(f"file '{filepath}'", emit))

        if emit: emit("[Step 2/4] Packer detection via entropy ...")
        results.append(self._exec(
            f"python3 -c \""
            f"import math,collections;"
            f"d=open('{filepath}','rb').read();"
            f"c=collections.Counter(d);"
            f"e=-sum((v/len(d))*math.log2(v/len(d)) for v in c.values() if v);"
            f"print(f'Entropy: {{e:.4f}}/8.0');"
            f"print('PACKED - High entropy detected!' if e>7 else 'Normal entropy - likely not packed')\"",
            emit))

        if emit: emit("[Step 3/4] Compiler/linker detection ...")
        results.append(self._exec(f"strings '{filepath}' | grep -iE 'gcc|msvc|delphi|upx|aspack|mpress|fsg|pe|nsis' | head -20", emit))

        if emit: emit("[Step 4/4] UPX unpacking attempt ...")
        results.append(self._exec(f"upx -t '{filepath}' 2>&1", emit))

        if emit: emit("DIE analysis complete.")
        return results
