"""
validate_rules.py — Rule File Schema Validator

Usage:
    python core/mitre/validate_rules.py

Validates all rule JSON files in ``core/mitre/rules/``.

Checks performed per file
-------------------------
1.  JSON is syntactically valid.
2.  Top-level keys ``category``, ``version``, ``rules`` are present.
3.  Every rule contains ALL required fields.
4.  ``severity`` ∈ {Critical, High, Medium, Low}.
5.  ``base_confidence`` is a float in [0.0, 1.0].
6.  ``mitre_technique_id`` matches ``^T\\d{4}(\\.\\d{3})?$``.
7.  Each condition has ``feature``, ``operator``, ``value``.
8.  ``operator`` ∈ {>, <, >=, <=, ==, !=, contains, exists, not_exists}.
9.  No duplicate ``rule_id`` values within a file.
10. ``conditions`` is a **non-empty** list.

Exit codes: 0 = all files pass, 1 = one or more failures.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# ── Constants ─────────────────────────────────────────────────────────────────
REQUIRED_TOP_KEYS = {"category", "version", "rules"}

REQUIRED_RULE_FIELDS = {
    "rule_id",
    "rule_name",
    "description",
    "category",
    "severity",
    "base_confidence",
    "mitre_technique_id",
    "mitre_technique_name",
    "mitre_tactic",
    "conditions",
    "recommendation",
}

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_OPERATORS = {">", "<", ">=", "<=", "==", "!=", "contains", "exists", "not_exists"}
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _colour(text: str, code: int) -> str:
    """ANSI colour wrapper — gracefully no-ops on non-TTY."""
    if not sys.stderr.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def _green(t: str) -> str:
    return _colour(t, 32)


def _red(t: str) -> str:
    return _colour(t, 31)


def _yellow(t: str) -> str:
    return _colour(t, 33)


# ── Validation logic ─────────────────────────────────────────────────────────
def validate_file(filepath: str) -> Tuple[int, List[str]]:
    """Validate a single rule JSON file.

    Parameters
    ----------
    filepath : str
        Absolute or relative path to the ``*_rules.json`` file.

    Returns
    -------
    (error_count, messages)
        A tuple with the total number of errors and a list of human-readable
        diagnostic messages (each prefixed with ``[ERROR]`` or ``[WARN]``).
    """
    errors: List[str] = []
    warnings: List[str] = []

    # 1. JSON validity
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        errors.append(f"[ERROR] Invalid JSON: {exc}")
        return len(errors), errors
    except OSError as exc:
        errors.append(f"[ERROR] Cannot read file: {exc}")
        return len(errors), errors

    if not isinstance(data, dict):
        errors.append("[ERROR] Top-level value must be a JSON object")
        return len(errors), errors

    # 2. Top-level keys
    missing_top = REQUIRED_TOP_KEYS - data.keys()
    if missing_top:
        errors.append(f"[ERROR] Missing top-level keys: {sorted(missing_top)}")

    rules_list = data.get("rules", [])
    if not isinstance(rules_list, list):
        errors.append("[ERROR] 'rules' must be a JSON array")
        return len(errors), errors + warnings

    # 3–10.  Per-rule checks
    seen_ids: Dict[str, int] = {}

    for idx, rule in enumerate(rules_list):
        prefix = f"  rule #{idx}"

        if not isinstance(rule, dict):
            errors.append(f"{prefix}: expected object, got {type(rule).__name__}")
            continue

        rule_id = rule.get("rule_id", f"<unknown#{idx}>")
        prefix = f"  rule '{rule_id}'"

        # 3. Required fields
        missing = REQUIRED_RULE_FIELDS - rule.keys()
        if missing:
            errors.append(f"{prefix}: missing fields {sorted(missing)}")

        # 4. Severity
        severity = rule.get("severity")
        if severity is not None and severity not in VALID_SEVERITIES:
            errors.append(
                f"{prefix}: invalid severity '{severity}' — must be one of {sorted(VALID_SEVERITIES)}"
            )

        # 5. base_confidence
        bc = rule.get("base_confidence")
        if bc is not None:
            try:
                bc_float = float(bc)
                if not 0.0 <= bc_float <= 1.0:
                    errors.append(f"{prefix}: base_confidence {bc_float} outside [0.0, 1.0]")
            except (TypeError, ValueError):
                errors.append(f"{prefix}: base_confidence '{bc}' is not a valid number")

        # 6. Technique ID format
        tech_id = rule.get("mitre_technique_id")
        if tech_id is not None and not TECHNIQUE_ID_RE.match(str(tech_id)):
            errors.append(
                f"{prefix}: mitre_technique_id '{tech_id}' does not match T####(.###)"
            )

        # 9. Duplicate rule_id
        if rule_id in seen_ids:
            errors.append(
                f"{prefix}: duplicate rule_id (first seen at rule #{seen_ids[rule_id]})"
            )
        seen_ids[rule_id] = idx

        # 10. Conditions: non-empty list
        conditions = rule.get("conditions")
        if conditions is not None:
            if not isinstance(conditions, list):
                errors.append(f"{prefix}: 'conditions' must be a list")
                continue
            if len(conditions) == 0:
                errors.append(f"{prefix}: 'conditions' must not be empty")
                continue

            # 7–8. Per-condition checks
            for cidx, cond in enumerate(conditions):
                cprefix = f"{prefix} cond #{cidx}"
                if not isinstance(cond, dict):
                    errors.append(f"{cprefix}: expected object, got {type(cond).__name__}")
                    continue

                for key in ("feature", "operator", "value"):
                    if key not in cond:
                        errors.append(f"{cprefix}: missing key '{key}'")

                op = cond.get("operator")
                if op is not None and op not in VALID_OPERATORS:
                    errors.append(
                        f"{cprefix}: unsupported operator '{op}' — must be one of {sorted(VALID_OPERATORS)}"
                    )

    return len(errors), errors + warnings


# ── CLI entry-point ───────────────────────────────────────────────────────────
def main() -> int:
    """Discover and validate all ``*_rules.json`` files.

    Returns
    -------
    int
        Exit code: 0 if all files pass, 1 otherwise.
    """
    rules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")

    if not os.path.isdir(rules_dir):
        print(f"Rules directory not found: {rules_dir}")
        print("Nothing to validate.")
        return 0

    rule_files = sorted(
        p for p in Path(rules_dir).glob("*_rules.json")
    )

    if not rule_files:
        print(f"No *_rules.json files found in {rules_dir}")
        print("Nothing to validate.")
        return 0

    total_files = len(rule_files)
    total_errors = 0
    passed = 0

    print("=" * 70)
    print("MITRE ATT&CK Rule Validator")
    print("=" * 70)

    for filepath in rule_files:
        relpath = os.path.relpath(filepath)
        err_count, messages = validate_file(str(filepath))
        total_errors += err_count

        if err_count == 0:
            print(f"\n{_green('PASS')}  {relpath}")
            passed += 1
        else:
            print(f"\n{_red('FAIL')}  {relpath}  ({err_count} error(s))")
            for msg in messages:
                print(f"      {msg}")

    # Summary
    print("\n" + "=" * 70)
    print("Summary")
    print("-" * 70)
    print(f"  Files checked : {total_files}")
    print(f"  Passed        : {_green(str(passed))}")
    print(f"  Failed        : {_red(str(total_files - passed))}")
    print(f"  Total errors  : {total_errors}")
    print("=" * 70)

    if total_errors > 0:
        print(f"\n{_red('VALIDATION FAILED')} — fix the errors above.")
        return 1
    else:
        print(f"\n{_green('ALL RULES VALID')} [OK]")
        return 0


if __name__ == "__main__":
    sys.exit(main())
