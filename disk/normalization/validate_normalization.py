"""
validate_normalization.py
=========================
Validates disk_normalized_events.json against the expected schema.

Usage:
    python disk/normalization/validate_normalization.py
    python disk/normalization/validate_normalization.py disk/normalized/disk_normalized_events.json
"""

import json
import os
import sys
from collections import Counter

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DISK_DIR     = os.path.dirname(SCRIPT_DIR)
DEFAULT_PATH = os.path.join(DISK_DIR, "normalized", "disk_normalized_events.json")

REQUIRED_FIELDS = [
    "event_id", "source", "inode", "inode_spec",
    "path", "filename", "extension",
    "is_directory", "is_deleted", "is_allocated",
    "is_orphan", "is_hidden", "is_executable", "double_extension",
    "in_suspicious_dir", "depth", "file_size", "mode", "alloc_status",
    "atime", "mtime", "ctime", "crtime",
    "timeline_ts", "mac_flags",
    "flag_m", "flag_a", "flag_c", "flag_b",
    "filesystem", "cluster_size", "sector_size",
]

BOOL_FIELDS = [
    "is_directory", "is_deleted", "is_allocated", "is_orphan",
    "is_hidden", "is_executable", "double_extension",
    "in_suspicious_dir", "flag_m", "flag_a", "flag_c", "flag_b",
]

INT_FIELDS  = ["event_id", "depth", "file_size"]
VALID_SOURCES = {"fls", "timeline"}


def validate(path: str) -> bool:
    print(f"[INFO] Validating: {path}")
    print()

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    n = len(data)
    print(f"  Total records : {n:,}")
    print()

    errors       = []
    source_ctr   = Counter()
    missing_flds = Counter()

    for i, rec in enumerate(data):
        rec_id = rec.get("event_id", i)

        # Missing fields
        for fld in REQUIRED_FIELDS:
            if fld not in rec:
                missing_flds[fld] += 1
                errors.append(f"Record {rec_id}: missing field '{fld}'")

        # Bool fields
        for fld in BOOL_FIELDS:
            if fld in rec and not isinstance(rec[fld], bool):
                errors.append(f"Record {rec_id}: '{fld}' should be bool, got {type(rec[fld]).__name__}")

        # Int fields
        for fld in INT_FIELDS:
            if fld in rec and not isinstance(rec[fld], int):
                errors.append(f"Record {rec_id}: '{fld}' should be int, got {type(rec[fld]).__name__}")

        # Source
        src = rec.get("source")
        if src not in VALID_SOURCES:
            errors.append(f"Record {rec_id}: invalid source '{src}'")
        else:
            source_ctr[src] += 1

        # file_size non-negative
        sz = rec.get("file_size")
        if isinstance(sz, int) and sz < 0:
            errors.append(f"Record {rec_id}: file_size < 0")

        if len(errors) > 200:
            errors.append("... (truncated at 200 errors)")
            break

    print("  Source distribution:")
    for src, cnt in sorted(source_ctr.items()):
        print(f"    {src:<12} : {cnt:,}")
    print()

    if missing_flds:
        print("  Missing field counts:")
        for fld, cnt in missing_flds.most_common(10):
            print(f"    {fld:<30} : {cnt}")
        print()

    n_errors = len(errors)
    if n_errors == 0:
        print("  Validation Errors : 0")
        print()
        print("  RESULT: ALL CHECKS PASSED")
    else:
        print(f"  Validation Errors : {n_errors}")
        for e in errors[:20]:
            print(f"    {e}")
        print()
        print("  RESULT: VALIDATION FAILED")

    return n_errors == 0


def main():
    path = sys.argv[1] if len(sys.argv) >= 2 else DEFAULT_PATH
    ok   = validate(path)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
