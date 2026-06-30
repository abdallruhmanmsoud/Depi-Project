"""
tsk_parser.py
=============
Stage 1 — Parser for The Sleuth Kit (TSK) forensic disk outputs.

Reads five TSK-generated files and merges them into a single
intermediate representation of every disk artifact.

Input files (all in the project root):
    fsstat.txt    — Filesystem metadata (NTFS volume statistics)
    fls.txt       — File listing (all files + dirs, including deleted)
    ils.txt       — Inode listing (allocated / deleted / unallocated)
    bodyfile.txt  — MAC times and sizes in bodyfile (pipe-delimited)
    timeline.txt  — Chronological timeline (mactime output)

Output:
    disk/raw/parsed_disk_events.txt

Design
------
* Streaming line-by-line — never loads a large file into memory.
* Merge by inode: bodyfile times enrich fls file records.
* Resilient: malformed lines are skipped and counted.
* Handles all fls type flags: r/r, d/d, -/r, r/-, d/-, -/d, V/V.

Format notes
------------
fls.txt:
    [+...] TYPE_FLAG INODE-ATTR-ID: FILENAME
    where TYPE_FLAG is one of: r/r d/d -/r r/- d/- -/d V/V

bodyfile.txt (mactime body format, 11 pipe-separated fields):
    md5|name|inode|mode_as_string|uid|gid|size|atime|mtime|ctime|crtime

ils.txt:
    st_ino|st_alloc|st_uid|st_gid|st_mtime|st_atime|st_ctime|st_crtime|st_mode|st_nlink|st_size
    st_alloc: 'f'=allocated, 'a'=allocated, 'u'=unallocated

timeline.txt (mactime output):
    DATE TIME  SIZE  MAC_FLAGS  MODE  UID  GID  INODE_SPEC  PATH

Usage:
    python disk/parser/tsk_parser.py [--root ...]  [--output ...]
"""

import argparse
import os
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DISK_DIR     = os.path.dirname(SCRIPT_DIR)
PROJECT_ROOT = os.path.dirname(DISK_DIR)

# ─── Suspicious path keywords ─────────────────────────────────────────────────
_SUSPICIOUS_DIRS = {
    "temp", "tmp", "downloads", "download", "desktop",
    "appdata\\local\\temp", "appdata/local/temp",
    "recycler", "$recycle.bin", "windows\\temp",
}

_EXEC_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js",
    "jar", "scr", "com", "msi", "hta", "pif", "reg",
}


# ─── fsstat parser ────────────────────────────────────────────────────────────

def parse_fsstat(filepath: str) -> Dict[str, Any]:
    """Parse fsstat.txt and return filesystem metadata dict."""
    info: Dict[str, Any] = {}
    if not os.path.exists(filepath):
        return info

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    def _get(pattern: str, text: str = content) -> Optional[str]:
        m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else None

    info["fs_type"]       = _get(r"File System Type:\s*(.+)")
    info["volume_serial"] = _get(r"Volume Serial Number:\s*(.+)")
    info["oem_name"]      = _get(r"OEM Name:\s*(.+)")
    info["version"]       = _get(r"Version:\s*(.+)")
    info["mft_entry_size"]= _get(r"Size of MFT Entries:\s*(\d+)")
    info["index_size"]    = _get(r"Size of Index Records:\s*(\d+)")
    info["root_inode"]    = _get(r"Root Directory:\s*(\d+)")

    # Inode range:  "Range: 0 - 297216"
    m_range = re.search(r"Range:\s*(\d+)\s*-\s*(\d+)", content)
    if m_range:
        info["inode_range_start"] = int(m_range.group(1))
        info["inode_range_end"]   = int(m_range.group(2))
        info["total_inodes"]      = int(m_range.group(2)) - int(m_range.group(1)) + 1

    info["sector_size"]   = _get(r"Sector Size:\s*(\d+)")
    info["cluster_size"]  = _get(r"Cluster Size:\s*(\d+)")

    # Total cluster range:  "Total Cluster Range: 0 - 15644158"
    m_clust = re.search(r"Total Cluster Range:\s*(\d+)\s*-\s*(\d+)", content)
    if m_clust:
        info["total_clusters"] = int(m_clust.group(2)) - int(m_clust.group(1)) + 1

    # Total sector range: "Total Sector Range: 0 - 125153278"
    m_sect = re.search(r"Total Sector Range:\s*(\d+)\s*-\s*(\d+)", content)
    if m_sect:
        info["total_sectors"] = int(m_sect.group(2)) - int(m_sect.group(1)) + 1
        if info.get("sector_size"):
            info["volume_size_bytes"] = info["total_sectors"] * int(info["sector_size"])

    # MFT cluster
    info["first_cluster_mft"] = _get(r"First Cluster of MFT:\s*(\d+)")

    return info


# ─── ils parser ───────────────────────────────────────────────────────────────

def parse_ils(filepath: str) -> Dict[str, Dict]:
    """
    Parse ils.txt.
    Returns dict keyed by str(inode) → inode metadata dict.

    Fields: st_ino, st_alloc, st_uid, st_gid, st_mtime, st_atime,
            st_ctime, st_crtime, st_mode, st_nlink, st_size
    """
    inodes: Dict[str, Dict] = {}
    if not os.path.exists(filepath):
        return inodes

    header_seen = False
    col_names: List[str] = []
    errors = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line or line.startswith("class|") or line.startswith("ils|"):
                continue
            if line.startswith("st_ino|"):
                col_names = line.split("|")
                header_seen = True
                continue
            if not header_seen:
                continue
            try:
                parts = line.split("|")
                if len(parts) < len(col_names):
                    continue
                rec = dict(zip(col_names, parts))
                inode_str = rec.get("st_ino", "").strip()
                if not inode_str:
                    continue
                # Normalise allocation status
                alloc = rec.get("st_alloc", "").strip().lower()
                rec["is_allocated"] = alloc in ("f", "a", "1")
                rec["is_deleted"]   = alloc in ("u", "0", "d")
                # Cast numeric fields
                for ts_field in ("st_mtime", "st_atime", "st_ctime", "st_crtime"):
                    val = rec.get(ts_field, "").strip()
                    rec[ts_field] = int(val) if val.lstrip("-").isdigit() else None
                sz = rec.get("st_size", "").strip()
                rec["st_size"] = int(sz) if sz.isdigit() else 0
                inodes[inode_str] = rec
            except Exception:
                errors += 1

    return inodes


# ─── bodyfile parser ──────────────────────────────────────────────────────────

def parse_bodyfile(filepath: str) -> Dict[str, Dict]:
    """
    Parse bodyfile.txt (11-column pipe-delimited mactime body format).
    Returns dict keyed by inode_spec (e.g. '104818-144-1') → record.

    Columns:
      md5 | name | inode_spec | mode | uid | gid | size |
      atime | mtime | ctime | crtime
    """
    body: Dict[str, Dict] = {}
    if not os.path.exists(filepath):
        return body

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            parts = line.split("|")
            if len(parts) < 11:
                continue
            try:
                inode_spec = parts[2].strip()
                name       = parts[1].strip()
                mode       = parts[3].strip()
                size_str   = parts[6].strip()
                atime_str  = parts[7].strip()
                mtime_str  = parts[8].strip()
                ctime_str  = parts[9].strip()
                crtime_str = parts[10].strip()

                def _ts(s: str) -> Optional[int]:
                    try:
                        v = int(s)
                        return v if v > 0 else None
                    except ValueError:
                        return None

                size = int(size_str) if size_str.isdigit() else 0

                rec = {
                    "inode_spec":  inode_spec,
                    "path":        name,
                    "mode":        mode,
                    "file_size":   size,
                    "atime":       _ts(atime_str),
                    "mtime":       _ts(mtime_str),
                    "ctime":       _ts(ctime_str),
                    "crtime":      _ts(crtime_str),
                }
                # Keep the record with the most complete timestamp
                existing = body.get(inode_spec)
                if not existing or size > existing.get("file_size", 0):
                    body[inode_spec] = rec
            except Exception:
                continue

    return body


# ─── fls parser ───────────────────────────────────────────────────────────────

# fls type-flag → (is_directory, meta_flag)
# meta_flag: 'r'=regular, 'd'=dir, '-'=deleted/reallocated
_FLS_TYPE = {
    "r/r": (False, "allocated"),
    "d/d": (True,  "allocated"),
    "-/r": (False, "deleted_reallocated"),
    "r/-": (False, "deleted"),
    "d/-": (True,  "deleted"),
    "-/d": (True,  "deleted_reallocated"),
    "v/v": (False, "virtual"),
    "V/V": (False, "virtual"),
    "l/l": (False, "allocated"),     # symlink
    "l/-": (False, "deleted"),
}

# Regex for fls line:  [DEPTH]TYPE  INODE-ATTR-ID: NAME
_FLS_RE = re.compile(
    r"^(\+*)"                          # group 1: depth indicators
    r"\s*([a-zA-Z\-]+/[a-zA-Z\-]+)"   # group 2: type flag (e.g. r/r)
    r"\s+"
    r"(\d+(?:-\d+)*)"                  # group 3: inode[-attr[-id]]
    r"(?:\s*\([^)]*\))?"               # optional (realloc)
    r":\s+"
    r"(.+)$"                           # group 4: filename
)


def _extract_extension(filename: str) -> str:
    """Return lowercase extension without dot, or '' if none."""
    # Handle double extensions (e.g. 'archive.tar.gz')
    base = filename.rsplit("(", 1)[0].strip()  # remove " ($FILE_NAME)" suffix
    _, dot, ext = base.rpartition(".")
    return ext.lower().strip() if dot else ""


def _is_hidden(filename: str) -> bool:
    """Heuristic: starts with '.' or '$' (NTFS system files)."""
    name = filename.lstrip()
    return name.startswith(".") or name.startswith("$")


def _is_double_extension(filename: str) -> bool:
    """Detect double extensions like evil.jpg.exe."""
    parts = filename.rsplit(".", 2)
    if len(parts) == 3:
        inner_ext = parts[1].lower()
        outer_ext = parts[2].lower()
        return (inner_ext in _EXEC_EXTENSIONS or
                outer_ext in _EXEC_EXTENSIONS)
    return False


def _path_in_suspicious_dir(path: str) -> bool:
    p_lower = path.lower().replace("\\", "/")
    return any(d in p_lower for d in _SUSPICIOUS_DIRS)


def _dir_depth(path: str) -> int:
    return path.count("/") + path.count("\\")


def iter_fls_records(
    filepath: str,
    body_index: Dict[str, Dict],
) -> Iterator[Dict[str, Any]]:
    """
    Stream fls.txt line by line.
    Yields one dict per file/directory entry.
    Enriches with bodyfile timestamps when available.
    """
    if not os.path.exists(filepath):
        return

    path_stack: List[str] = []   # tracks directory path as we descend

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\r\n")
            if not line:
                continue

            m = _FLS_RE.match(line)
            if not m:
                continue

            depth_str  = m.group(1)
            type_flag  = m.group(2)
            inode_spec = m.group(3)
            filename   = m.group(4).strip()

            depth = len(depth_str)  # number of '+' chars

            # Maintain path stack
            while len(path_stack) >= depth + 1:
                path_stack.pop()

            # Build full path
            path = "/" + "/".join(path_stack + [filename]) if path_stack else "/" + filename

            is_dir, alloc_status = _FLS_TYPE.get(type_flag, (False, "unknown"))

            # Inode base (strip attribute info)
            inode_base = inode_spec.split("-")[0]

            # Extension and flags
            ext         = _extract_extension(filename)
            is_hidden   = _is_hidden(filename)
            is_deleted  = "deleted" in alloc_status
            is_orphan   = (filename.startswith("OrphanFile") or
                           "(deleted" in filename or
                           "$OrphanFiles" in filename)
            double_ext  = _is_double_extension(filename)
            is_exec     = ext in _EXEC_EXTENSIONS
            in_susp_dir = _path_in_suspicious_dir(path)

            # Enrich from bodyfile
            bf = body_index.get(inode_spec, {})
            file_size = bf.get("file_size", 0)
            atime     = bf.get("atime")
            mtime     = bf.get("mtime")
            ctime     = bf.get("ctime")
            crtime    = bf.get("crtime")
            mode      = bf.get("mode", "")

            # Push directory to stack for children
            if is_dir and not is_deleted:
                path_stack.append(filename)

            yield {
                "source":         "fls",
                "inode_spec":     inode_spec,
                "inode":          inode_base,
                "type_flag":      type_flag,
                "path":           path,
                "filename":       filename,
                "extension":      ext,
                "is_directory":   is_dir,
                "is_deleted":     is_deleted,
                "is_allocated":   alloc_status == "allocated",
                "is_orphan":      is_orphan,
                "is_hidden":      is_hidden,
                "is_exec":        is_exec,
                "double_extension": double_ext,
                "in_suspicious_dir": in_susp_dir,
                "alloc_status":   alloc_status,
                "depth":          depth,
                "file_size":      file_size,
                "atime":          atime,
                "mtime":          mtime,
                "ctime":          ctime,
                "crtime":         crtime,
                "mode":           mode,
            }


# ─── timeline parser ──────────────────────────────────────────────────────────

# timeline.txt mactime format:
# DATE TIME   SIZE   MAC_FLAGS   MODE   UID   GID   INODE_SPEC   PATH(S)
# Columns are whitespace-separated; multiple paths may follow INODE_SPEC

_TIMELINE_RE = re.compile(
    r"^(\w{3} \w{3} \d{2} \d{4} \d{2}:\d{2}:\d{2})"   # 1: timestamp string
    r"\s+(\d+)"                                           # 2: size
    r"\s+([\.macb]+)"                                     # 3: MAC flags
    r"\s+(\S+)"                                           # 4: mode
    r"\s+(\d+)"                                           # 5: uid
    r"\s+(\d+)"                                           # 6: gid
    r"\s+(\S+)"                                           # 7: inode_spec
    r"\s+(.+)$"                                           # 8: path(s)
)

_DATE_FORMATS = [
    "%a %b %d %Y %H:%M:%S",   # mactime: Thu Jun 29 2023 14:30:00
]

def _parse_timeline_ts(ts_str: str) -> Optional[int]:
    for fmt in _DATE_FORMATS:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return int(dt.replace(tzinfo=timezone.utc).timestamp())
        except ValueError:
            pass
    return None


def iter_timeline_records(filepath: str) -> Iterator[Dict[str, Any]]:
    """Stream timeline.txt and yield one dict per event."""
    if not os.path.exists(filepath):
        return

    last_ts = None   # mactime groups multiple records under same timestamp
    last_ts_str = ""

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\r\n")
            if not line:
                continue

            # Continuation line: same timestamp, different file
            # These start with spaces/tabs (blank date field)
            if line[0] in (" ", "\t"):
                # Parse remaining parts from stripped line
                stripped = line.strip()
                sub_m = re.match(
                    r"(\d+)\s+([\.macb]+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.+)$",
                    stripped,
                )
                if sub_m and last_ts is not None:
                    yield {
                        "source":      "timeline",
                        "timestamp":   last_ts,
                        "timestamp_str": last_ts_str,
                        "file_size":   int(sub_m.group(1)),
                        "mac_flags":   sub_m.group(2),
                        "mode":        sub_m.group(3),
                        "uid":         sub_m.group(4),
                        "gid":         sub_m.group(5),
                        "inode_spec":  sub_m.group(6),
                        "path":        sub_m.group(7).strip(),
                        "flag_m":      "m" in sub_m.group(2),
                        "flag_a":      "a" in sub_m.group(2),
                        "flag_c":      "c" in sub_m.group(2),
                        "flag_b":      "b" in sub_m.group(2),
                    }
                continue

            m = _TIMELINE_RE.match(line)
            if not m:
                continue

            ts_str     = m.group(1)
            ts         = _parse_timeline_ts(ts_str)
            last_ts    = ts
            last_ts_str = ts_str

            yield {
                "source":        "timeline",
                "timestamp":     ts,
                "timestamp_str": ts_str,
                "file_size":     int(m.group(2)),
                "mac_flags":     m.group(3),
                "mode":          m.group(4),
                "uid":           m.group(5),
                "gid":           m.group(6),
                "inode_spec":    m.group(7),
                "path":          m.group(8).strip(),
                "flag_m":        "m" in m.group(3),
                "flag_a":        "a" in m.group(3),
                "flag_c":        "c" in m.group(3),
                "flag_b":        "b" in m.group(3),
            }


# ─── Text renderer ────────────────────────────────────────────────────────────

def _ts_str(ts: Optional[int]) -> str:
    if ts is None or ts <= 0:
        return "N/A"
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def render_output(
    fsinfo: Dict,
    fls_records: List[Dict],
    ils_inodes:  Dict,
    timeline_records: List[Dict],
    output_path: str,
) -> None:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    # Counters
    total_files    = sum(1 for r in fls_records if not r["is_directory"])
    total_dirs     = sum(1 for r in fls_records if r["is_directory"])
    deleted_files  = sum(1 for r in fls_records if r["is_deleted"] and not r["is_directory"])
    deleted_dirs   = sum(1 for r in fls_records if r["is_deleted"] and r["is_directory"])
    alloc_files    = sum(1 for r in fls_records if r["is_allocated"] and not r["is_directory"])
    orphan_files   = sum(1 for r in fls_records if r["is_orphan"])

    with open(output_path, "w", encoding="utf-8") as f:
        # ── Filesystem info ───────────────────────────────────────────────────
        f.write("=" * 60 + "\n")
        f.write("  FILESYSTEM INFORMATION\n")
        f.write("=" * 60 + "\n\n")
        for k, v in fsinfo.items():
            f.write(f"  {k:<30} : {v}\n")
        f.write("\n")

        # ── FLS records ───────────────────────────────────────────────────────
        f.write("=" * 60 + "\n")
        f.write("  FILE SYSTEM ENTRIES  (from fls.txt)\n")
        f.write("=" * 60 + "\n\n")

        for rec in fls_records:
            f.write("  " + "-" * 56 + "\n")
            f.write(f"  Source           : {rec['source']}\n")
            f.write(f"  Inode            : {rec['inode_spec']}\n")
            f.write(f"  Path             : {rec['path']}\n")
            f.write(f"  Filename         : {rec['filename']}\n")
            f.write(f"  Extension        : {rec['extension'] or 'N/A'}\n")
            f.write(f"  Is Directory     : {rec['is_directory']}\n")
            f.write(f"  Is Deleted       : {rec['is_deleted']}\n")
            f.write(f"  Is Allocated     : {rec['is_allocated']}\n")
            f.write(f"  Is Orphan        : {rec['is_orphan']}\n")
            f.write(f"  Is Hidden        : {rec['is_hidden']}\n")
            f.write(f"  Is Executable    : {rec['is_exec']}\n")
            f.write(f"  Double Extension : {rec['double_extension']}\n")
            f.write(f"  Suspicious Dir   : {rec['in_suspicious_dir']}\n")
            f.write(f"  Depth            : {rec['depth']}\n")
            f.write(f"  File Size        : {rec['file_size']}\n")
            f.write(f"  Created          : {_ts_str(rec['crtime'])}\n")
            f.write(f"  Modified         : {_ts_str(rec['mtime'])}\n")
            f.write(f"  Accessed         : {_ts_str(rec['atime'])}\n")
            f.write(f"  Changed          : {_ts_str(rec['ctime'])}\n")
            f.write(f"  Mode             : {rec['mode'] or 'N/A'}\n")
            f.write(f"  Alloc Status     : {rec['alloc_status']}\n")
            f.write("\n")

        # ── Timeline events ───────────────────────────────────────────────────
        f.write("=" * 60 + "\n")
        f.write("  TIMELINE EVENTS  (from timeline.txt)\n")
        f.write("=" * 60 + "\n\n")

        for ev in timeline_records[:5000]:   # cap for readability
            f.write(f"  {ev.get('timestamp_str','?'):<26}"
                    f"  {ev.get('mac_flags',''):<8}"
                    f"  sz={ev.get('file_size',0):>10}"
                    f"  {ev.get('path','')[:80]}\n")

        if len(timeline_records) > 5000:
            f.write(f"\n  ... and {len(timeline_records)-5000:,} more timeline events (truncated for readability)\n")
        f.write("\n")

        # ── ILS inodes ────────────────────────────────────────────────────────
        f.write("=" * 60 + "\n")
        f.write("  INODE RECORDS  (from ils.txt)\n")
        f.write("=" * 60 + "\n\n")
        alloc_c   = sum(1 for v in ils_inodes.values() if v.get("is_allocated"))
        deleted_c = sum(1 for v in ils_inodes.values() if v.get("is_deleted"))
        f.write(f"  Total inode records : {len(ils_inodes):,}\n")
        f.write(f"  Allocated           : {alloc_c:,}\n")
        f.write(f"  Deleted/Unallocated : {deleted_c:,}\n\n")

        # ── Summary ───────────────────────────────────────────────────────────
        f.write("=" * 60 + "\n")
        f.write("  PARSE SUMMARY\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"  Total FLS records   : {len(fls_records):,}\n")
        f.write(f"  Files               : {total_files:,}\n")
        f.write(f"  Directories         : {total_dirs:,}\n")
        f.write(f"  Deleted files       : {deleted_files:,}\n")
        f.write(f"  Deleted directories : {deleted_dirs:,}\n")
        f.write(f"  Allocated files     : {alloc_files:,}\n")
        f.write(f"  Orphan files        : {orphan_files:,}\n")
        f.write(f"  Timeline events     : {len(timeline_records):,}\n")
        f.write(f"  ILS inode records   : {len(ils_inodes):,}\n")
        f.write(f"  Alloc inodes (ILS)  : {alloc_c:,}\n")
        f.write(f"  Deleted inodes(ILS) : {deleted_c:,}\n")
        f.write("\n")


# ─── Main ─────────────────────────────────────────────────────────────────────

class TskParser:
    def __init__(self, root: str = PROJECT_ROOT):
        self.root = root
        self.fsinfo: Dict[str, Any] = {}
        self.ils_inodes: Dict[str, Dict] = {}
        self.body_index: Dict[str, Dict] = {}
        self.fls_records: List[Dict] = []
        self.timeline_records: List[Dict] = []
        self.errors = 0

    def _path(self, name: str) -> str:
        return os.path.join(self.root, name)

    def parse(self) -> None:
        import time

        print("[INFO] Parsing fsstat.txt ...")
        self.fsinfo = parse_fsstat(self._path("fsstat.txt"))
        print(f"       FS type: {self.fsinfo.get('fs_type','?')}, "
              f"cluster size: {self.fsinfo.get('cluster_size','?')}")

        print("[INFO] Parsing ils.txt ...")
        t0 = time.time()
        self.ils_inodes = parse_ils(self._path("ils.txt"))
        print(f"       {len(self.ils_inodes):,} inode records in {time.time()-t0:.1f}s")

        print("[INFO] Parsing bodyfile.txt ...")
        t0 = time.time()
        self.body_index = parse_bodyfile(self._path("bodyfile.txt"))
        print(f"       {len(self.body_index):,} body records in {time.time()-t0:.1f}s")

        print("[INFO] Parsing fls.txt (streaming, enriched from bodyfile) ...")
        t0 = time.time()
        self.fls_records = list(iter_fls_records(
            self._path("fls.txt"), self.body_index))
        print(f"       {len(self.fls_records):,} file records in {time.time()-t0:.1f}s")

        print("[INFO] Parsing timeline.txt (streaming) ...")
        t0 = time.time()
        self.timeline_records = list(iter_timeline_records(
            self._path("timeline.txt")))
        print(f"       {len(self.timeline_records):,} timeline events in {time.time()-t0:.1f}s")


def main():
    ap = argparse.ArgumentParser(description="TSK Forensic Disk Parser")
    ap.add_argument("--root",   "-r",
                    default=PROJECT_ROOT,
                    help="Project root containing all TSK files")
    ap.add_argument("--output", "-o",
                    default=os.path.join(DISK_DIR, "raw", "parsed_disk_events.txt"))
    args = ap.parse_args()

    print("=" * 52)
    print("  Disk AI — TSK Parser")
    print("=" * 52)
    print(f"  Input root : {args.root}")
    print(f"  Output     : {args.output}")
    print()

    parser = TskParser(root=args.root)
    parser.parse()

    print()
    print("[INFO] Writing output ...")
    render_output(
        parser.fsinfo,
        parser.fls_records,
        parser.ils_inodes,
        parser.timeline_records,
        args.output,
    )
    print(f"[INFO] Written : {args.output}")
    print()

    # ── Console summary ───────────────────────────────────────────────────────
    fls  = parser.fls_records
    ils  = parser.ils_inodes
    tl   = parser.timeline_records

    print("=" * 44)
    print("  Parse Summary")
    print("=" * 44)
    print(f"  FS type            : {parser.fsinfo.get('fs_type','?')}")
    print(f"  Total FLS records  : {len(fls):,}")
    print(f"  Files              : {sum(1 for r in fls if not r['is_directory']):,}")
    print(f"  Directories        : {sum(1 for r in fls if r['is_directory']):,}")
    print(f"  Deleted            : {sum(1 for r in fls if r['is_deleted']):,}")
    print(f"  Allocated          : {sum(1 for r in fls if r['is_allocated']):,}")
    print(f"  Orphan             : {sum(1 for r in fls if r['is_orphan']):,}")
    print(f"  Timeline events    : {len(tl):,}")
    print(f"  ILS inode records  : {len(ils):,}")
    print("=" * 44)


if __name__ == "__main__":
    main()
