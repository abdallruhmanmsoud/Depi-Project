"""
disk_feature_builder.py
=======================
Stage 3 — Disk Feature Extraction for the Disk AI Pipeline.

Reads ONLY disk/normalized/disk_normalized_events.json.
Never reads raw TSK files directly.

Generates a fixed-schema feature vector of 90–120 meaningful features
and writes it to disk/features/disk_feature_vector.json.

Feature Groups
--------------
1.  Filesystem Metadata   (8 features)
2.  File Statistics       (12 features)
3.  Extension Distribution (40 features)
4.  Temporal Features     (20 features)
5.  Inode Features        (6 features)
6.  Suspicious Indicators (14 features)
7.  Composite Scores      (8 features)

Total: 108 features

Usage:
    python disk/features/disk_feature_builder.py
    python disk/features/disk_feature_builder.py --input disk/normalized/disk_normalized_events.json
"""

import argparse
import json
import math
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DISK_DIR     = os.path.dirname(SCRIPT_DIR)

DEFAULT_INPUT  = os.path.join(DISK_DIR, "normalized", "disk_normalized_events.json")
DEFAULT_OUTPUT = os.path.join(DISK_DIR, "features",   "disk_feature_vector.json")

# ─── Extension sets ───────────────────────────────────────────────────────────
EXEC_EXTENSIONS = {
    "exe","dll","sys","bat","cmd","ps1","vbs","js","jar",
    "scr","com","msi","hta","pif","reg","sh","py","rb",
}
DOC_EXTENSIONS  = {"doc","docx","xls","xlsx","ppt","pptx","pdf","txt","csv","xml","json","odt","ods"}
ARCHIVE_EXTENSIONS = {"zip","rar","7z","cab","iso","img","tar","gz","bz2","xz"}
MEDIA_EXTENSIONS   = {"jpg","jpeg","png","gif","bmp","tiff","mp4","avi","mov","mp3","wav","flac","mkv"}
SCRIPT_EXTENSIONS  = {"ps1","vbs","js","bat","cmd","sh","py","rb","pl","hta"}
TEMP_EXTENSIONS    = {"tmp","log","bak","old","~","swp"}

# All extensions tracked individually
TRACKED_EXTENSIONS = [
    # Executables
    "exe","dll","sys","bat","cmd","ps1","vbs","js","jar","scr","com","msi","hta","pif","reg",
    # Documents
    "doc","docx","xls","xlsx","ppt","pptx","pdf","txt","csv","xml","json",
    # Archives
    "zip","rar","7z","cab","iso","img",
    # Media
    "jpg","png","gif","bmp","mp4","avi","mov",
    # Temp / Logs
    "tmp","log","bak",
    # Other notable
    "lnk","url","inf","ini","cfg",
]

# ─── Suspicious directory keywords ────────────────────────────────────────────
_TEMP_DIRS    = {"temp","tmp","windows/temp","appdata/local/temp"}
_DOWNLOAD_DIRS= {"downloads","download"}
_DESKTOP_DIRS = {"desktop","desktop/"}
_RECYCLE_DIRS = {"recycler","$recycle.bin","$recycled"}

def _in_dir(path: str, dirs: set) -> bool:
    p = (path or "").lower().replace("\\", "/")
    return any(d in p for d in dirs)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _safe_ratio(num: float, den: float, default: float = 0.0) -> float:
    return round(num / den, 6) if den > 0 else default

def _ts_to_hour(ts: Optional[int]) -> Optional[int]:
    if not ts or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).hour
    except Exception:
        return None

def _ts_to_weekday(ts: Optional[int]) -> Optional[int]:
    if not ts or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).weekday()   # 0=Mon, 6=Sun
    except Exception:
        return None

def _is_night(hour: Optional[int]) -> bool:
    if hour is None:
        return False
    return hour < 6 or hour >= 22

def _is_weekend(weekday: Optional[int]) -> bool:
    return weekday in (5, 6) if weekday is not None else False


# ─── Main feature extractor ───────────────────────────────────────────────────

class DiskFeatureBuilder:

    def extract(self, input_path: str) -> Dict[str, Any]:
        """Load normalized JSON and return the full feature vector."""
        with open(input_path, "r", encoding="utf-8") as f:
            records = json.load(f)

        return self._build(records)

    def _build(self, records: List[Dict]) -> Dict[str, Any]:
        fv: Dict[str, Any] = {}

        # ── Split by source ───────────────────────────────────────────────────
        fls_recs  = [r for r in records if r.get("source") == "fls"]
        tl_recs   = [r for r in records if r.get("source") == "timeline"]

        # ── 1. Filesystem Metadata ─────────────────────────────────────────────
        # Read from first record that has filesystem info
        fs_rec = next((r for r in records if r.get("filesystem")), {})
        fv["filesystem_type"]   = fs_rec.get("filesystem")
        fv["cluster_size"]      = fs_rec.get("cluster_size") or 0
        fv["sector_size"]       = fs_rec.get("sector_size") or 0

        # Derive volume size from cluster data if available
        # (total_clusters * cluster_size is embedded in fsstat but not in schema;
        #  we approximate from the largest file size seen as a minimum bound)
        max_sz = max((r.get("file_size") or 0 for r in fls_recs), default=0)
        fv["max_single_file_size"] = max_sz
        total_bytes = sum(r.get("file_size") or 0 for r in fls_recs)
        fv["total_data_bytes"]     = total_bytes
        avg_sz_all = round(
            total_bytes / len(fls_recs), 2) if fls_recs else 0.0
        fv["avg_file_size_bytes"]  = avg_sz_all

        # MFT/inode range (from records that have timeline context)
        inode_nums = []
        for r in fls_recs:
            try:
                inode_nums.append(int(r["inode"]))
            except (TypeError, ValueError, KeyError):
                pass
        fv["inode_range_observed"] = (max(inode_nums) - min(inode_nums)
                                       if len(inode_nums) >= 2 else 0)

        # ── 2. File Statistics ─────────────────────────────────────────────────
        files_only = [r for r in fls_recs if not r.get("is_directory")]
        dirs_only  = [r for r in fls_recs if r.get("is_directory")]

        fv["total_files"]       = len(files_only)
        fv["total_directories"] = len(dirs_only)
        fv["total_entries"]     = len(fls_recs)

        deleted   = [r for r in fls_recs if r.get("is_deleted")]
        allocated = [r for r in fls_recs if r.get("is_allocated")]
        orphans   = [r for r in fls_recs if r.get("is_orphan")]
        hidden    = [r for r in fls_recs if r.get("is_hidden")]

        fv["deleted_files"]       = sum(1 for r in deleted if not r.get("is_directory"))
        fv["deleted_directories"] = sum(1 for r in deleted if r.get("is_directory"))
        fv["hidden_files"]        = sum(1 for r in hidden  if not r.get("is_directory"))
        fv["orphan_files"]        = len(orphans)
        fv["allocated_files"]     = sum(1 for r in allocated if not r.get("is_directory"))

        # Average filename length (non-deleted files only)
        fnames = [
            len(r.get("filename") or "")
            for r in files_only if not r.get("is_deleted")
        ]
        fv["avg_filename_length"] = round(
            sum(fnames) / len(fnames), 2) if fnames else 0.0

        # Maximum directory depth
        depths = [r.get("depth") or 0 for r in fls_recs]
        fv["max_directory_depth"] = max(depths, default=0)
        fv["avg_directory_depth"] = round(
            sum(depths) / len(depths), 2) if depths else 0.0

        # Average files per directory
        fv["avg_files_per_directory"] = _safe_ratio(
            len(files_only), max(len(dirs_only), 1))

        # Deletion ratio
        fv["deletion_ratio"] = _safe_ratio(len(deleted), len(fls_recs))
        fv["allocation_ratio"] = _safe_ratio(len(allocated), len(fls_recs))

        # ── 3. Extension Distribution ──────────────────────────────────────────
        ext_ctr = Counter(
            (r.get("extension") or "").lower()
            for r in files_only
        )
        total_files_n = max(len(files_only), 1)

        for ext in TRACKED_EXTENSIONS:
            fv[f"ext_{ext}_count"] = ext_ctr.get(ext, 0)
            fv[f"ext_{ext}_ratio"] = _safe_ratio(ext_ctr.get(ext, 0), total_files_n)

        # Group counts
        fv["exec_file_count"]    = sum(ext_ctr.get(e, 0) for e in EXEC_EXTENSIONS)
        fv["doc_file_count"]     = sum(ext_ctr.get(e, 0) for e in DOC_EXTENSIONS)
        fv["archive_file_count"] = sum(ext_ctr.get(e, 0) for e in ARCHIVE_EXTENSIONS)
        fv["media_file_count"]   = sum(ext_ctr.get(e, 0) for e in MEDIA_EXTENSIONS)
        fv["script_file_count"]  = sum(ext_ctr.get(e, 0) for e in SCRIPT_EXTENSIONS)
        fv["temp_file_count"]    = sum(ext_ctr.get(e, 0) for e in TEMP_EXTENSIONS)
        fv["unique_extensions"]  = len(ext_ctr)

        # ── 4. Temporal Features ───────────────────────────────────────────────
        # Collect all valid timestamps from fls records
        all_ts = []
        crtime_ts, mtime_ts, atime_ts, ctime_ts = [], [], [], []
        for r in fls_recs:
            for field, lst in [("crtime", crtime_ts), ("mtime", mtime_ts),
                                ("atime", atime_ts),  ("ctime", ctime_ts)]:
                v = r.get(field)
                if v and v > 0:
                    lst.append(v)
                    all_ts.append(v)

        if all_ts:
            fv["earliest_timestamp"] = min(all_ts)
            fv["latest_timestamp"]   = max(all_ts)
            fv["timeline_duration"]  = max(all_ts) - min(all_ts)
            fv["avg_timestamp"]      = round(sum(all_ts) / len(all_ts))
        else:
            fv["earliest_timestamp"] = 0
            fv["latest_timestamp"]   = 0
            fv["timeline_duration"]  = 0
            fv["avg_timestamp"]      = 0

        # File age (seconds between crtime and mtime — proxy for lifespan)
        age_list = []
        for r in fls_recs:
            cr = r.get("crtime")
            mt = r.get("mtime")
            if cr and mt and mt > 0 and cr > 0 and mt >= cr:
                age_list.append(mt - cr)
        fv["avg_file_age_seconds"] = round(
            sum(age_list) / len(age_list)) if age_list else 0

        # Activity density: events per day over observation window
        duration_days = fv["timeline_duration"] / 86400 if fv["timeline_duration"] > 0 else 1
        fv["activity_density"] = _safe_ratio(len(all_ts), duration_days)

        # Creation / modification / deletion rates (events per day)
        fv["creation_rate"]     = _safe_ratio(len(crtime_ts),  duration_days)
        fv["modification_rate"] = _safe_ratio(len(mtime_ts),   duration_days)

        # Timeline records rates
        tl_ts = [r.get("timeline_ts") for r in tl_recs
                 if r.get("timeline_ts") and r["timeline_ts"] > 0]
        fv["timeline_event_count"] = len(tl_ts)
        fv["timeline_density"] = _safe_ratio(len(tl_ts), max(duration_days, 1))

        # Peak activity hour and day (from all timestamps)
        hours    = [_ts_to_hour(ts) for ts in all_ts if ts]
        weekdays = [_ts_to_weekday(ts) for ts in all_ts if ts]
        hour_ctr = Counter(h for h in hours    if h is not None)
        day_ctr  = Counter(d for d in weekdays if d is not None)

        fv["peak_activity_hour"] = (
            hour_ctr.most_common(1)[0][0] if hour_ctr else -1)
        fv["peak_activity_day"]  = (
            day_ctr.most_common(1)[0][0] if day_ctr else -1)
        fv["weekend_activity"]   = sum(1 for d in weekdays if _is_weekend(d))
        fv["night_activity"]     = sum(1 for h in hours    if _is_night(h))
        fv["weekend_activity_ratio"] = _safe_ratio(fv["weekend_activity"], max(len(weekdays), 1))
        fv["night_activity_ratio"]   = _safe_ratio(fv["night_activity"],   max(len(hours), 1))

        # Creation/deletion bursts: count timestamps within 60s windows
        def _count_bursts(timestamps: List[int], window: int = 60, threshold: int = 10) -> int:
            if not timestamps:
                return 0
            ts_sorted = sorted(timestamps)
            bursts, i = 0, 0
            while i < len(ts_sorted):
                j = i
                while j < len(ts_sorted) and ts_sorted[j] - ts_sorted[i] <= window:
                    j += 1
                if j - i >= threshold:
                    bursts += 1
                i = j
            return bursts

        fv["creation_bursts"]     = _count_bursts(crtime_ts)
        fv["modification_bursts"] = _count_bursts(mtime_ts)
        fv["deletion_bursts"]     = _count_bursts(
            [r.get("crtime") or 0 for r in deleted if r.get("crtime")])

        # Timestamp gaps: std-dev of inter-event intervals
        tl_ts_sorted = sorted(t for t in tl_ts if t > 0)
        if len(tl_ts_sorted) >= 2:
            gaps = [tl_ts_sorted[i+1] - tl_ts_sorted[i]
                    for i in range(len(tl_ts_sorted)-1)]
            mean_gap = sum(gaps) / len(gaps)
            var_gap  = sum((g - mean_gap)**2 for g in gaps) / len(gaps)
            fv["timestamp_gap_std"] = round(math.sqrt(var_gap), 2)
            fv["timestamp_gap_mean"] = round(mean_gap, 2)
        else:
            fv["timestamp_gap_std"]  = 0.0
            fv["timestamp_gap_mean"] = 0.0

        # ── 5. Inode Features ──────────────────────────────────────────────────
        total_inode_recs = len(fls_recs)
        alloc_inodes  = sum(1 for r in fls_recs if r.get("is_allocated"))
        deleted_inodes= sum(1 for r in fls_recs if r.get("is_deleted"))
        orphan_inodes = sum(1 for r in fls_recs if r.get("is_orphan"))

        fv["allocated_inode_ratio"] = _safe_ratio(alloc_inodes,   total_inode_recs)
        fv["deleted_inode_ratio"]   = _safe_ratio(deleted_inodes,  total_inode_recs)
        fv["orphan_inode_ratio"]    = _safe_ratio(orphan_inodes,   total_inode_recs)

        # Metadata density: inode-range coverage
        inode_count = fv["inode_range_observed"]
        fv["metadata_density"] = _safe_ratio(total_inode_recs, max(inode_count, 1))

        # Inode reuse: deleted inodes with valid timestamps (may have been reused)
        reused = sum(
            1 for r in fls_recs
            if r.get("is_deleted") and r.get("crtime") and r["crtime"] > 0
        )
        fv["deleted_with_timestamps"] = reused

        # Files with no timestamps at all
        no_ts = sum(
            1 for r in files_only
            if not any([r.get("crtime"), r.get("mtime"), r.get("atime"), r.get("ctime")])
        )
        fv["files_with_no_timestamp"] = no_ts

        # ── 6. Suspicious Indicators ──────────────────────────────────────────
        exec_files = [r for r in files_only if r.get("is_executable")]

        fv["executables_in_temp"]      = sum(
            1 for r in exec_files if _in_dir(r.get("path",""), _TEMP_DIRS))
        fv["executables_in_downloads"] = sum(
            1 for r in exec_files if _in_dir(r.get("path",""), _DOWNLOAD_DIRS))
        fv["executables_on_desktop"]   = sum(
            1 for r in exec_files if _in_dir(r.get("path",""), _DESKTOP_DIRS))
        fv["deleted_executables"]      = sum(
            1 for r in exec_files if r.get("is_deleted"))
        fv["hidden_executables"]       = sum(
            1 for r in exec_files if r.get("is_hidden"))
        fv["double_extension_count"]   = sum(
            1 for r in files_only if r.get("double_extension"))
        fv["suspicious_dir_files"]     = sum(
            1 for r in files_only if r.get("in_suspicious_dir"))

        # Large deletion windows: time span of deleted files' timestamps
        del_ts = sorted(
            r.get("crtime") or 0
            for r in deleted if r.get("crtime") and r["crtime"] > 0
        )
        if len(del_ts) >= 2:
            fv["deletion_time_span"] = del_ts[-1] - del_ts[0]
        else:
            fv["deletion_time_span"] = 0

        # Executables created then quickly deleted (crtime and is_deleted)
        fv["exec_created_then_deleted"] = sum(
            1 for r in exec_files if r.get("is_deleted"))

        # High modification frequency: files modified more recently than created
        hm = sum(
            1 for r in files_only
            if r.get("mtime") and r.get("crtime") and
               r["mtime"] > 0 and r["crtime"] > 0 and
               r["mtime"] > r["crtime"] + 86400  # modified >1 day after creation
        )
        fv["high_modification_count"] = hm

        # Persistence indicators: files in startup/run locations
        _PERSISTENCE_DIRS = {
            "startup", "start menu", "shell:startup",
            "currentversion/run", "currentversion\\run",
            "tasks", "scheduled tasks", "windowsapps",
        }
        fv["persistence_indicators"] = sum(
            1 for r in files_only
            if _in_dir(r.get("path", ""), _PERSISTENCE_DIRS)
        )

        # Script files in suspicious locations
        script_files = [r for r in files_only
                        if (r.get("extension") or "") in SCRIPT_EXTENSIONS]
        fv["scripts_in_suspicious_dirs"] = sum(
            1 for r in script_files if r.get("in_suspicious_dir"))

        # LNK (shortcut) count — often used for persistence
        fv["lnk_file_count"] = ext_ctr.get("lnk", 0)

        # Recently modified vs. created (within 1 hour)
        recent_mod = sum(
            1 for r in files_only
            if r.get("mtime") and r.get("crtime") and
               r["mtime"] > 0 and r["crtime"] > 0 and
               abs(r["mtime"] - r["crtime"]) <= 3600
        )
        fv["recently_created_and_modified"] = recent_mod

        # ── 7. Composite Scores ────────────────────────────────────────────────
        total_f = max(fv["total_files"], 1)
        total_e = max(fv["total_entries"], 1)

        # Filesystem Health Score: (1 - deletion_ratio) * (1 - orphan_ratio) * 100
        fv["filesystem_health_score"] = round(
            (1.0 - fv["deletion_ratio"]) *
            (1.0 - _safe_ratio(len(orphans), total_e)) * 100, 4)

        # Deletion Score: weighted sum of deletion indicators
        fv["deletion_score"] = round(
            fv["deleted_files"]       * 1.0 +
            fv["deleted_directories"] * 2.0 +
            fv["deleted_executables"] * 5.0 +
            fv["deletion_bursts"]     * 10.0, 4)

        # Execution Risk Score
        fv["execution_risk_score"] = round(
            fv["exec_file_count"]          * 0.1 +
            fv["executables_in_temp"]      * 5.0 +
            fv["executables_in_downloads"] * 3.0 +
            fv["executables_on_desktop"]   * 2.0 +
            fv["deleted_executables"]      * 8.0 +
            fv["hidden_executables"]       * 10.0 +
            fv["double_extension_count"]   * 15.0 +
            fv["exec_created_then_deleted"]* 12.0, 4)

        # Persistence Score
        fv["persistence_score"] = round(
            fv["persistence_indicators"]    * 5.0 +
            fv["lnk_file_count"]            * 2.0 +
            fv["scripts_in_suspicious_dirs"]* 8.0, 4)

        # Timeline Risk Score
        fv["timeline_risk_score"] = round(
            fv["creation_bursts"]     * 5.0 +
            fv["modification_bursts"] * 3.0 +
            fv["deletion_bursts"]     * 8.0 +
            fv["night_activity_ratio"]    * 20.0 +
            fv["weekend_activity_ratio"]  * 5.0, 4)

        # Artifact Density Score
        fv["artifact_density_score"] = round(
            fv["total_entries"]          * 0.001 +
            fv["unique_extensions"]      * 0.5 +
            fv["orphan_files"]           * 2.0 +
            fv["files_with_no_timestamp"]* 0.5, 4)

        # User Activity Score
        fv["user_activity_score"] = round(
            fv["total_files"]            * 0.01 +
            fv["doc_file_count"]         * 0.5 +
            fv["media_file_count"]       * 0.3 +
            fv["archive_file_count"]     * 1.0 +
            fv["recently_created_and_modified"] * 2.0, 4)

        # Overall Disk Risk Score
        fv["overall_disk_risk_score"] = round(
            fv["execution_risk_score"] * 1.0 +
            fv["deletion_score"]       * 0.5 +
            fv["persistence_score"]    * 1.5 +
            fv["timeline_risk_score"]  * 1.0 +
            fv["artifact_density_score"] * 0.2, 4)

        return fv

    def save(self, output_path: str, vector: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(vector, f, indent=2, ensure_ascii=False, default=str)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Disk AI — Feature Builder")
    ap.add_argument("--input",  "-i", default=DEFAULT_INPUT)
    ap.add_argument("--output", "-o", default=DEFAULT_OUTPUT)
    args = ap.parse_args()

    print("=" * 52)
    print("  Disk AI — Feature Builder")
    print("=" * 52)
    print(f"  Input  : {args.input}")
    print(f"  Output : {args.output}")
    print()

    t0 = time.time()

    builder = DiskFeatureBuilder()
    print("[INFO] Extracting features ...")
    vector = builder.extract(args.input)

    print(f"[INFO] Writing : {args.output}")
    builder.save(args.output, vector)

    elapsed = time.time() - t0

    # ── Summary ───────────────────────────────────────────────────────────────
    numeric_features = {k: v for k, v in vector.items() if isinstance(v, (int, float))}
    cat_features     = {k: v for k, v in vector.items() if not isinstance(v, (int, float))}

    print()
    print("=" * 52)
    print("  Feature Extraction Summary")
    print("=" * 52)
    print(f"  Total features       : {len(vector)}")
    print(f"  Numeric features     : {len(numeric_features)}")
    print(f"  Categorical features : {len(cat_features)}")
    print(f"  NaN values           : {sum(1 for v in numeric_features.values() if isinstance(v, float) and math.isnan(v))}")
    print(f"  Inf values           : {sum(1 for v in numeric_features.values() if isinstance(v, float) and math.isinf(v))}")
    print(f"  Null numeric         : {sum(1 for v in numeric_features.values() if v is None)}")
    print()
    print("  Key Feature Values:")

    key_feats = [
        "total_files", "total_directories", "deleted_files",
        "orphan_files", "hidden_files", "exec_file_count",
        "deleted_executables", "hidden_executables",
        "executables_in_temp", "executables_in_downloads",
        "double_extension_count", "persistence_indicators",
        "creation_bursts", "deletion_bursts",
        "night_activity_ratio", "deletion_ratio",
        "execution_risk_score", "persistence_score",
        "deletion_score", "timeline_risk_score",
        "overall_disk_risk_score",
    ]
    for k in key_feats:
        print(f"    {k:<40} : {vector.get(k)}")

    print()
    print(f"  Elapsed              : {elapsed:.1f}s")
    print("=" * 52)
    print()


if __name__ == "__main__":
    main()
