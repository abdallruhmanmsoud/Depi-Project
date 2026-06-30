"""
disk_normalizer.py
==================
Stage 2 — Normalizer for the Disk AI Pipeline.

Consumes the parsed records produced by tsk_parser.py and
converts every file/directory/timeline event into a standardised
JSON schema that the Feature Builder can consume.

Input:  (live — calls the parser directly and processes records)
Output: disk/normalized/disk_normalized_events.json

Schema (per record)
-------------------
Every record carries these fields (null when unavailable):

    event_id          int       Sequential record identifier
    source            str       "fls" | "timeline"
    inode             str       Inode identifier (base number)
    inode_spec        str       Full inode-attr-id spec
    path              str       Full path of file/directory
    filename          str       Basename only
    extension         str|null  Lowercase extension without dot
    is_directory      bool
    is_deleted        bool
    is_allocated      bool
    is_orphan         bool
    is_hidden         bool
    is_executable     bool
    double_extension  bool
    in_suspicious_dir bool
    depth             int       Directory nesting depth
    file_size         int       Size in bytes (0 if unknown)
    mode              str|null  Permission string (e.g. r/rrwxrwxrwx)
    alloc_status      str       "allocated"|"deleted"|"orphan"|"virtual"|"unknown"
    atime             int|null  Access time (Unix epoch)
    mtime             int|null  Modification time (Unix epoch)
    ctime             int|null  Change time (Unix epoch)
    crtime            int|null  Creation time (Unix epoch)
    timeline_ts       int|null  Event timestamp from timeline (for tl records)
    mac_flags         str|null  MAC flags string (for timeline records)
    flag_m            bool      Modified flag
    flag_a            bool      Accessed flag
    flag_c            bool      Changed flag
    flag_b            bool      Born/created flag
    filesystem        str|null  Filesystem type from fsstat
    cluster_size      int|null
    sector_size       int|null

Usage:
    python disk/normalization/disk_normalizer.py
    python disk/normalization/disk_normalizer.py --output disk/normalized/disk_normalized_events.json
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, Iterator, List, Optional

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DISK_DIR     = os.path.dirname(SCRIPT_DIR)
PROJECT_ROOT = os.path.dirname(DISK_DIR)

sys.path.insert(0, os.path.join(DISK_DIR, "parser"))
from tsk_parser import TskParser

DEFAULT_OUTPUT = os.path.join(DISK_DIR, "normalized", "disk_normalized_events.json")


# ─── Schema fields (defines canonical column order) ───────────────────────────

SCHEMA_FIELDS = [
    "event_id", "source", "inode", "inode_spec",
    "path", "filename", "extension",
    "is_directory", "is_deleted", "is_allocated",
    "is_orphan", "is_hidden", "is_executable", "double_extension",
    "in_suspicious_dir", "depth",
    "file_size", "mode", "alloc_status",
    "atime", "mtime", "ctime", "crtime",
    "timeline_ts", "mac_flags",
    "flag_m", "flag_a", "flag_c", "flag_b",
    "filesystem", "cluster_size", "sector_size",
]


def _safe_bool(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return False


def _safe_int(val: Any) -> Optional[int]:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _basename(path: str) -> str:
    """Extract filename from path."""
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def normalize_fls_record(
    rec: Dict[str, Any],
    event_id: int,
    fs_type: Optional[str],
    cluster_size: Optional[int],
    sector_size: Optional[int],
) -> Dict[str, Any]:
    """Normalise one fls record to the canonical schema."""
    path     = rec.get("path", "") or ""
    filename = rec.get("filename", "") or _basename(path)

    return {
        "event_id":         event_id,
        "source":           "fls",
        "inode":            rec.get("inode") or None,
        "inode_spec":       rec.get("inode_spec") or None,
        "path":             path or None,
        "filename":         filename or None,
        "extension":        rec.get("extension") or None,
        "is_directory":     _safe_bool(rec.get("is_directory")),
        "is_deleted":       _safe_bool(rec.get("is_deleted")),
        "is_allocated":     _safe_bool(rec.get("is_allocated")),
        "is_orphan":        _safe_bool(rec.get("is_orphan")),
        "is_hidden":        _safe_bool(rec.get("is_hidden")),
        "is_executable":    _safe_bool(rec.get("is_exec")),
        "double_extension": _safe_bool(rec.get("double_extension")),
        "in_suspicious_dir": _safe_bool(rec.get("in_suspicious_dir")),
        "depth":            _safe_int(rec.get("depth")) or 0,
        "file_size":        _safe_int(rec.get("file_size")) or 0,
        "mode":             rec.get("mode") or None,
        "alloc_status":     rec.get("alloc_status") or "unknown",
        "atime":            _safe_int(rec.get("atime")),
        "mtime":            _safe_int(rec.get("mtime")),
        "ctime":            _safe_int(rec.get("ctime")),
        "crtime":           _safe_int(rec.get("crtime")),
        "timeline_ts":      None,
        "mac_flags":        None,
        "flag_m":           False,
        "flag_a":           False,
        "flag_c":           False,
        "flag_b":           False,
        "filesystem":       fs_type,
        "cluster_size":     cluster_size,
        "sector_size":      sector_size,
    }


def normalize_timeline_record(
    rec: Dict[str, Any],
    event_id: int,
    fs_type: Optional[str],
    cluster_size: Optional[int],
    sector_size: Optional[int],
) -> Dict[str, Any]:
    """Normalise one timeline record to the canonical schema."""
    path     = rec.get("path", "") or ""
    filename = _basename(path)
    ext      = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    return {
        "event_id":         event_id,
        "source":           "timeline",
        "inode":            rec.get("inode_spec", "").split("-")[0] or None,
        "inode_spec":       rec.get("inode_spec") or None,
        "path":             path or None,
        "filename":         filename or None,
        "extension":        ext or None,
        "is_directory":     path.rstrip("/").endswith("/") if path else False,
        "is_deleted":       False,
        "is_allocated":     True,
        "is_orphan":        False,
        "is_hidden":        filename.startswith((".", "$")) if filename else False,
        "is_executable":    ext in {
            "exe","dll","sys","bat","cmd","ps1","vbs",
            "js","jar","scr","com","msi","hta","pif"},
        "double_extension": False,
        "in_suspicious_dir": any(
            d in path.lower().replace("\\", "/")
            for d in {"temp","tmp","downloads","desktop","recycle"}
        ),
        "depth":            path.count("/") + path.count("\\"),
        "file_size":        _safe_int(rec.get("file_size")) or 0,
        "mode":             rec.get("mode") or None,
        "alloc_status":     "allocated",
        "atime":            rec.get("timestamp") if rec.get("flag_a") else None,
        "mtime":            rec.get("timestamp") if rec.get("flag_m") else None,
        "ctime":            rec.get("timestamp") if rec.get("flag_c") else None,
        "crtime":           rec.get("timestamp") if rec.get("flag_b") else None,
        "timeline_ts":      rec.get("timestamp"),
        "mac_flags":        rec.get("mac_flags"),
        "flag_m":           _safe_bool(rec.get("flag_m")),
        "flag_a":           _safe_bool(rec.get("flag_a")),
        "flag_c":           _safe_bool(rec.get("flag_c")),
        "flag_b":           _safe_bool(rec.get("flag_b")),
        "filesystem":       fs_type,
        "cluster_size":     cluster_size,
        "sector_size":      sector_size,
    }


# ─── Validator ────────────────────────────────────────────────────────────────

def validate_record(rec: Dict[str, Any], idx: int) -> List[str]:
    """Return list of validation error strings (empty = valid)."""
    errors = []
    if rec.get("event_id") is None:
        errors.append(f"[{idx}] Missing event_id")
    if rec.get("source") not in ("fls", "timeline"):
        errors.append(f"[{idx}] Invalid source: {rec.get('source')}")
    for bool_field in ("is_directory", "is_deleted", "is_allocated",
                       "is_orphan", "is_hidden", "is_executable",
                       "double_extension", "in_suspicious_dir",
                       "flag_m", "flag_a", "flag_c", "flag_b"):
        if not isinstance(rec.get(bool_field), bool):
            errors.append(f"[{idx}] {bool_field} is not bool: {rec.get(bool_field)!r}")
    if not isinstance(rec.get("depth"), int):
        errors.append(f"[{idx}] depth is not int")
    if not isinstance(rec.get("file_size"), int):
        errors.append(f"[{idx}] file_size is not int")
    return errors


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Disk AI — Normalizer")
    ap.add_argument("--root",   default=PROJECT_ROOT)
    ap.add_argument("--output", "-o", default=DEFAULT_OUTPUT)
    ap.add_argument("--no-timeline", action="store_true",
                    help="Skip timeline records (faster, smaller output)")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    print("=" * 52)
    print("  Disk AI — Normalizer")
    print("=" * 52)
    print(f"  Output : {args.output}")
    print()

    t0 = time.time()

    # ── Run parser ─────────────────────────────────────────────────────────────
    parser = TskParser(root=args.root)
    parser.parse()

    fs_type      = parser.fsinfo.get("fs_type")
    cluster_size = _safe_int(parser.fsinfo.get("cluster_size"))
    sector_size  = _safe_int(parser.fsinfo.get("sector_size"))

    print()
    print("[INFO] Normalizing records ...")

    events: List[Dict[str, Any]] = []
    validation_errors: List[str] = []
    event_id = 1

    # ── FLS records ────────────────────────────────────────────────────────────
    for rec in parser.fls_records:
        norm = normalize_fls_record(rec, event_id, fs_type, cluster_size, sector_size)
        errs = validate_record(norm, event_id)
        validation_errors.extend(errs)
        events.append(norm)
        event_id += 1

    print(f"[INFO] FLS records normalised : {len(parser.fls_records):,}")

    # ── Timeline records ───────────────────────────────────────────────────────
    if not args.no_timeline:
        for rec in parser.timeline_records:
            norm = normalize_timeline_record(rec, event_id, fs_type, cluster_size, sector_size)
            errs = validate_record(norm, event_id)
            validation_errors.extend(errs)
            events.append(norm)
            event_id += 1
        print(f"[INFO] Timeline records norm. : {len(parser.timeline_records):,}")

    # ── Write JSON ─────────────────────────────────────────────────────────────
    print(f"[INFO] Writing {len(events):,} records to JSON ...")
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(events, f, ensure_ascii=False, default=str)

    elapsed = time.time() - t0

    print()
    print("=" * 52)
    print("  Normalization Summary")
    print("=" * 52)
    print(f"  Total events        : {len(events):,}")
    print(f"  FLS records         : {len(parser.fls_records):,}")
    if not args.no_timeline:
        print(f"  Timeline records    : {len(parser.timeline_records):,}")
    print(f"  Validation errors   : {len(validation_errors)}")
    if validation_errors:
        for e in validation_errors[:10]:
            print(f"    {e}")
    print(f"  Output              : {args.output}")
    print(f"  Elapsed             : {elapsed:.1f}s")
    print("=" * 52)
    print()


if __name__ == "__main__":
    main()
