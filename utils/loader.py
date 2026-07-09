"""
Dynamic plugin loader.
Scans the tools/ directory and imports every module that exposes a subclass
of ``BaseTool``.
"""

import importlib
import importlib.util
import logging
import os
import sys
from typing import Dict, Type

logger = logging.getLogger(__name__)


def discover_tools(tools_dir: str) -> Dict[str, Type]:
    """Return a mapping of *tool_id* → *tool class* for every valid plugin
    found under *tools_dir*.

    A valid plugin is a ``.py`` file (not ``__init__.py``, not ``base.py``)
    that contains at least one class whose ``tool_id`` attribute is set.
    """
    from tools.base import BaseTool  # local import to avoid circular deps

    discovered: Dict[str, Type] = {}

    if not os.path.isdir(tools_dir):
        logger.warning("Tools directory does not exist: %s", tools_dir)
        return discovered

    for filename in sorted(os.listdir(tools_dir)):
        if not filename.endswith(".py"):
            continue
        if filename in ("__init__.py", "base.py"):
            continue
        if filename.startswith("_"):
            continue

        module_name = f"tools.{filename[:-3]}"
        spec = importlib.util.spec_from_file_location(
            module_name, os.path.join(tools_dir, filename)
        )
        if spec is None or spec.loader is None:
            continue

        try:
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception:
            logger.exception("Failed to load module %s", module_name)
            continue

        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            if (
                isinstance(obj, type)
                and issubclass(obj, BaseTool)
                and obj is not BaseTool
                and getattr(obj, "tool_id", None)
            ):
                discovered[obj.tool_id] = obj
                logger.info("Discovered tool: %s (%s)", obj.tool_id, obj.name)

    return discovered
