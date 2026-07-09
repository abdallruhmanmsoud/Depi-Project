"""ResourceHacker — Extract resources from PE files."""
from __future__ import annotations
import os
from typing import Callable
from tools.base import BaseTool, StepResult

class ResourceHackerTool(BaseTool):
    tool_id = "resourcehacker"
    name = "ResourceHacker"
    description = "Extract and analyse embedded resources from PE files: icons, strings, manifests, and version info."
    accepted_extensions = [".exe", ".dll", ".sys", ".scr"]
    system_prerequisites = ["wrestool", "strings"]

    def run(self, filepath: str, emit: Callable[[str], None] | None = None) -> list[StepResult]:
        results = []
        output_dir = os.path.join(os.path.dirname(filepath), "resources")
        os.makedirs(output_dir, exist_ok=True)

        if emit: emit("[Step 1/3] Listing embedded resources ...")
        results.append(self._exec(f"wrestool -l '{filepath}' 2>&1", emit))

        if emit: emit("[Step 2/3] Extracting resources ...")
        results.append(self._exec(f"wrestool -x --raw -o '{output_dir}' '{filepath}' 2>&1", emit))

        if emit: emit("[Step 3/3] Listing extracted files ...")
        results.append(self._exec(f"ls -lh '{output_dir}' 2>&1", emit))

        if emit: emit("ResourceHacker analysis complete.")
        return results
