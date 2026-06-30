"""
disk_dataset_builder.py
=======================
Stage 4 — Disk AI Dataset Builder.

Architecture (strict requirement — features come from the REAL pipeline):

    Synthetic normalized records   (compact, feature-complete)
            ↓
    DiskFeatureBuilder._build(records)       ← REAL feature builder, unchanged
            ↓
    171-Feature Vector
            ↓
    CSV row

Every case uses the real DiskFeatureBuilder._build() so feature computation
logic is never bypassed or approximated.

Record counts are kept compact (200–600 per case) so the builder runs in
~2 minutes for 1,600 cases while still exercising all 171 feature dimensions.

Outputs:
    disk/dataset/disk_train.csv    — 1200 SAFE cases
    disk/dataset/disk_test.csv     — 1200 SAFE + 400 MALICIOUS (shuffled)

Usage:
    python disk/dataset/disk_dataset_builder.py
    python disk/dataset/disk_dataset_builder.py --safe 1200 --malicious 400
"""

import argparse
import csv
import json
import math
import os
import random
import sys
import time
from typing import Any, Dict, List, Optional

import numpy as np

# ─── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DISK_DIR     = os.path.dirname(SCRIPT_DIR)
PROJECT_ROOT = os.path.dirname(DISK_DIR)

sys.path.insert(0, os.path.join(DISK_DIR, "features"))
from disk_feature_builder import DiskFeatureBuilder

TRAIN_CSV = os.path.join(SCRIPT_DIR, "disk_train.csv")
TEST_CSV  = os.path.join(SCRIPT_DIR, "disk_test.csv")

# ─── Extension taxonomy (must match feature builder) ─────────────────────────
EXEC_EXTS    = ["exe","dll","sys","bat","cmd","ps1","vbs","js","jar","scr","com","msi","hta","pif","reg"]
DOC_EXTS     = ["doc","docx","xls","xlsx","ppt","pptx","pdf","txt","csv","xml","json"]
ARCHIVE_EXTS = ["zip","rar","7z","cab","iso","img"]
MEDIA_EXTS   = ["jpg","png","gif","bmp","mp4","avi","mov"]
SCRIPT_EXTS  = ["ps1","vbs","js","bat","cmd","sh","py","hta"]
TEMP_EXTS    = ["tmp","log","bak","lnk","url","inf","ini","cfg"]
EXEC_SET     = set(EXEC_EXTS)

ALL_COMMON_EXTS = EXEC_EXTS + DOC_EXTS + ARCHIVE_EXTS + MEDIA_EXTS + TEMP_EXTS

# ─── Path templates ───────────────────────────────────────────────────────────
SYS_PATHS      = ["/Windows/System32/", "/Windows/SysWOW64/", "/Program Files/", "/Program Files (x86)/"]
USER_PATHS     = ["/Users/User/Documents/", "/Users/User/Downloads/", "/Users/User/Desktop/"]
TEMP_PATHS     = ["/Windows/Temp/", "/AppData/Local/Temp/", "/Temp/"]
DOWNLOAD_PATHS = ["/Downloads/", "/Users/User/Downloads/"]
DESKTOP_PATHS  = ["/Desktop/", "/Users/User/Desktop/", "/ProgramData/Desktop/"]
STARTUP_PATHS  = [
    "/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/",
    "/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/",
    "/Windows/System32/Tasks/",
]
SUSP_PATHS = TEMP_PATHS + DOWNLOAD_PATHS + DESKTOP_PATHS

FS_TYPES      = ["NTFS","NTFS","NTFS","FAT32","exFAT"]
CLUSTER_SIZES = [512, 4096, 4096, 8192, 16384]

BASE_EPOCH   = 1_500_000_000   # ~2017
RECENT_EPOCH = 1_782_000_000   # ~2026

# ─── Record factory ───────────────────────────────────────────────────────────

def _ts(lo: int = BASE_EPOCH, hi: int = RECENT_EPOCH) -> int:
    return random.randint(lo, hi)

def _make(
    path: str, filename: str, ext: str,
    is_dir:      bool = False,
    is_deleted:  bool = False,
    is_orphan:   bool = False,
    is_hidden:   bool = False,
    depth:       int  = 2,
    size:        int  = 0,
    fs_type:     str  = "NTFS",
    cluster:     int  = 4096,
    crtime:      Optional[int] = None,
    mtime:       Optional[int] = None,
) -> Dict[str, Any]:
    cr = crtime or _ts()
    mt = mtime  or cr + random.randint(0, 86400 * 180)
    at = mt + random.randint(0, 86400 * 30)
    ct = mt

    is_exec   = ext in EXEC_SET
    susp_dirs = {"temp","tmp","downloads","desktop","recycle"}
    in_susp   = any(d in path.lower() for d in susp_dirs)
    # Double extension: something.doc.exe
    double    = is_exec and "." in filename.rsplit(".", 1)[0]

    return {
        "event_id":          random.randint(1, 999_999),
        "source":            "fls",
        "inode":             str(random.randint(100, 299_999)),
        "inode_spec":        f"{random.randint(100,299999)}-128-1",
        "path":              path,
        "filename":          filename,
        "extension":         ext,
        "is_directory":      is_dir,
        "is_deleted":        is_deleted,
        "is_allocated":      not is_deleted,
        "is_orphan":         is_orphan,
        "is_hidden":         is_hidden,
        "is_executable":     is_exec,
        "double_extension":  double,
        "in_suspicious_dir": in_susp,
        "depth":             depth,
        "file_size":         size or random.randint(1024, 5_000_000),
        "mode":              "r/rrwxrwxrwx",
        "alloc_status":      "deleted" if is_deleted else "allocated",
        "atime":             at,
        "mtime":             mt,
        "ctime":             ct,
        "crtime":            cr,
        "timeline_ts":       None,
        "mac_flags":         None,
        "flag_m":            False,
        "flag_a":            False,
        "flag_c":            False,
        "flag_b":            False,
        "filesystem":        fs_type,
        "cluster_size":      cluster,
        "sector_size":       512,
    }

def _dir(path: str, depth: int, fs: str, cl: int) -> Dict[str, Any]:
    return _make(path, path.rstrip("/").rsplit("/",1)[-1], "",
                 is_dir=True, depth=depth, fs_type=fs, cluster=cl,
                 size=0)


# ─── Compact SAFE record generator ───────────────────────────────────────────

PROFILES = [
    "workstation", "developer", "server", "fresh_install",
    "active_user", "legacy", "document_heavy", "media_station",
]

def _profile_params(profile: str, rng: np.random.Generator) -> Dict:
    """Return (n_sys, n_docs, n_media, n_arch, n_exec, n_script, n_temp, n_lnk)."""
    i = lambda lo, hi: int(rng.integers(lo, hi))
    P = {
        "workstation":    dict(sys=80, docs=30, media=20, arch=10, exec=60, script=5,  temp=5,  lnk=5),
        "developer":      dict(sys=60, docs=10, media=5,  arch=20, exec=120,script=40, temp=10, lnk=3),
        "server":         dict(sys=100,docs=5,  media=2,  arch=10, exec=80, script=15, temp=20, lnk=2),
        "fresh_install":  dict(sys=120,docs=2,  media=1,  arch=2,  exec=40, script=2,  temp=3,  lnk=1),
        "active_user":    dict(sys=60, docs=60, media=40, arch=15, exec=50, script=5,  temp=8,  lnk=15),
        "legacy":         dict(sys=90, docs=40, media=10, arch=30, exec=100,script=8,  temp=12, lnk=5),
        "document_heavy": dict(sys=50, docs=120,media=10, arch=5,  exec=30, script=3,  temp=4,  lnk=8),
        "media_station":  dict(sys=50, docs=10, media=100,arch=15, exec=30, script=3,  temp=5,  lnk=5),
    }[profile]
    # Add variance ±30%
    return {k: max(1, int(v * rng.uniform(0.7, 1.3))) for k, v in P.items()}


def generate_safe_records(profile: str, seed: int) -> List[Dict]:
    """Compact SAFE record set (~200–400 records). All feature groups covered."""
    random.seed(seed)
    rng = np.random.default_rng(seed)

    fs  = random.choice(FS_TYPES)
    cl  = random.choice(CLUSTER_SIZES)
    p   = _profile_params(profile, rng)

    base_cr = _ts(BASE_EPOCH, RECENT_EPOCH - 86400 * 30)
    recs: List[Dict] = []

    def add(path, fname, ext, **kw):
        recs.append(_make(path, fname, ext, fs_type=fs, cluster=cl,
                          crtime=base_cr + random.randint(0, 86400*365), **kw))

    # System files
    for i in range(p["sys"]):
        ext = random.choices(EXEC_EXTS, weights=[4,8,4,2,2,2,1,1,1,1,1,2,1,1,1])[0]
        add(random.choice(SYS_PATHS), f"sys{i}.{ext}", ext,
            depth=3, size=random.randint(1024, 10_000_000))

    # Docs
    for i in range(p["docs"]):
        ext = random.choice(DOC_EXTS)
        add(random.choice(USER_PATHS), f"doc{i}.{ext}", ext,
            depth=random.randint(1,4), size=random.randint(512, 10_000_000))

    # Media
    for i in range(p["media"]):
        ext = random.choice(MEDIA_EXTS)
        add(random.choice(USER_PATHS), f"media{i}.{ext}", ext,
            depth=random.randint(1,5), size=random.randint(100_000, 500_000_000))

    # Archives
    for i in range(p["arch"]):
        ext = random.choice(ARCHIVE_EXTS)
        add(random.choice(USER_PATHS + ["/Downloads/"]), f"arch{i}.{ext}", ext,
            depth=random.randint(1,3), size=random.randint(10_000, 200_000_000))

    # Executables (programs)
    for i in range(p["exec"]):
        ext = random.choice(EXEC_EXTS)
        add(random.choice(SYS_PATHS + ["/Program Files/"]), f"prog{i}.{ext}", ext,
            depth=random.randint(2,5), size=random.randint(1024, 50_000_000))

    # Scripts
    for i in range(p["script"]):
        ext = random.choice(SCRIPT_EXTS)
        add(random.choice(USER_PATHS + SYS_PATHS), f"script{i}.{ext}", ext,
            depth=random.randint(1,4), size=random.randint(100, 500_000))

    # Temp / log
    for i in range(p["temp"]):
        ext = random.choice(TEMP_EXTS)
        add(random.choice(TEMP_PATHS), f"tmp{i}.{ext}", ext,
            depth=3, size=random.randint(100, 1_000_000))

    # LNK shortcuts
    for i in range(p["lnk"]):
        add(random.choice(DESKTOP_PATHS + STARTUP_PATHS), f"link{i}.lnk", "lnk",
            depth=random.randint(2,4), size=1024)

    # Normal benign persistence (1–5 items)
    for i in range(random.randint(1, 5)):
        ext = random.choice(["exe","lnk","bat"])
        add(random.choice(STARTUP_PATHS), f"autost{i}.{ext}", ext, depth=4)

    # Directories
    for p_dir in SYS_PATHS + USER_PATHS + TEMP_PATHS + STARTUP_PATHS:
        recs.append(_dir(p_dir, depth=random.randint(1,3), fs=fs, cl=cl))

    # Orphan (0–2)
    for i in range(random.randint(0, 2)):
        ext = random.choice(["dll","sys","exe"])
        add(random.choice(SYS_PATHS), f"orphan{i}.{ext}", ext,
            depth=3, is_orphan=True)

    # Hidden system files (normal — $MFT, $LogFile etc.)
    for i in range(random.randint(2, 8)):
        ext = random.choice(["","sys","dll"])
        add("/Windows/System32/", f"$hidden{i}.{ext}", ext,
            depth=2, is_hidden=True, size=random.randint(1024, 50_000_000))

    return recs


# ─── MALICIOUS record generators ─────────────────────────────────────────────

ATTACK_TYPES = [
    "ransomware",            "malware_dropper",       "persistence_abuse",
    "wiper",                 "double_extension",      "hidden_exec_abuse",
    "burst_creation",        "burst_deletion",        "startup_abuse",
    "suspicious_temp_exec",  "exec_proliferation",    "high_orphan",
    "abnormal_filesystem",   "timestamp_stomping",
]


def generate_malicious_records(attack_type: str, seed: int) -> List[Dict]:
    """Inject attack pattern into a base SAFE record set."""
    profile = PROFILES[seed % len(PROFILES)]
    recs    = generate_safe_records(profile, seed + 500_000)
    if not recs:
        return recs

    fs  = recs[0]["filesystem"]
    cl  = recs[0]["cluster_size"]
    now = RECENT_EPOCH - random.randint(0, 3600)

    random.seed(seed)
    rng = np.random.default_rng(seed)

    def add(path, fname, ext, **kw):
        # Only set crtime default if caller did not supply it
        if "crtime" not in kw:
            kw["crtime"] = now + random.randint(0, 60)
        recs.append(_make(path, fname, ext, fs_type=fs, cluster=cl, **kw))

    # ── Attack injections ────────────────────────────────────────────────────
    if attack_type == "ransomware":
        enc_exts = ["encrypted","locked","crypt","zepto","locky"]
        files = [r for r in recs if not r["is_directory"] and r.get("extension") in set(DOC_EXTS)]
        for r in files:
            r["extension"] = random.choice(enc_exts)
            r["mtime"]     = now + random.randint(0, 3600)
        for i in range(random.randint(30, 80)):
            add(random.choice(USER_PATHS), f"HOW_TO_DECRYPT_{i}.txt", "txt",
                size=1024, mtime=now)
        for i in range(random.randint(5, 20)):
            add(random.choice(TEMP_PATHS), f"crypt_{i}.exe", "exe",
                size=random.randint(100_000,2_000_000), is_deleted=True, mtime=now)

    elif attack_type == "malware_dropper":
        for i in range(random.randint(40, 150)):
            p = random.choice(TEMP_PATHS + DOWNLOAD_PATHS)
            add(p, f"update_{i}.exe", "exe",
                size=random.randint(50_000,5_000_000),
                is_hidden=(random.random() < 0.4), mtime=now + i)
        for i in range(random.randint(10, 50)):
            add(random.choice(TEMP_PATHS), f"drop_{i}.exe", "exe",
                size=random.randint(10_000,500_000),
                is_deleted=True, is_hidden=True, mtime=now)

    elif attack_type == "persistence_abuse":
        for i in range(random.randint(30, 200)):
            ext = random.choice(["exe","bat","ps1","vbs","lnk"])
            add(random.choice(STARTUP_PATHS), f"persist_{i}.{ext}", ext,
                size=random.randint(1024,500_000), mtime=now + i)

    elif attack_type == "wiper":
        files = [r for r in recs if not r["is_directory"]]
        n_del = int(len(files) * rng.uniform(0.35, 0.85))
        for r in random.sample(files, min(n_del, len(files))):
            r["is_deleted"]   = True
            r["is_allocated"] = False
            r["alloc_status"] = "deleted"
            r["mtime"]        = now + random.randint(0, 60)
        add(random.choice(TEMP_PATHS), "wiper.exe", "exe",
            size=random.randint(100_000, 2_000_000), is_deleted=True, mtime=now)

    elif attack_type == "double_extension":
        for i in range(random.randint(50, 300)):
            decoy = random.choice(DOC_EXTS + MEDIA_EXTS)
            fname = f"document_{i}.{decoy}.exe"
            add(random.choice(DOWNLOAD_PATHS + DESKTOP_PATHS + TEMP_PATHS),
                fname, "exe", size=random.randint(50_000,5_000_000), mtime=now + i)

    elif attack_type == "hidden_exec_abuse":
        for i in range(random.randint(30, 200)):
            ext = random.choice(EXEC_EXTS)
            add(random.choice(SYS_PATHS + TEMP_PATHS), f".hidden_{i}.{ext}", ext,
                is_hidden=True, size=random.randint(10_000, 5_000_000), mtime=now + i)

    elif attack_type == "burst_creation":
        for i in range(random.randint(200, 800)):
            ext = random.choice(EXEC_EXTS + SCRIPT_EXTS)
            add(random.choice(SUSP_PATHS), f"burst_{i}.{ext}", ext,
                size=random.randint(1024, 1_000_000),
                crtime=now + i, mtime=now + i)

    elif attack_type == "burst_deletion":
        files = [r for r in recs if not r["is_directory"]]
        n_del = int(len(files) * rng.uniform(0.20, 0.70))
        for r in random.sample(files, min(n_del, len(files))):
            r["is_deleted"]   = True
            r["is_allocated"] = False
            r["alloc_status"] = "deleted"
            r["mtime"]        = now + random.randint(0, 30)

    elif attack_type == "startup_abuse":
        for i in range(random.randint(20, 150)):
            ext = random.choice(["exe","bat","ps1","vbs","com"])
            add(random.choice(STARTUP_PATHS), f"svc_{i}.{ext}", ext,
                size=random.randint(1024, 2_000_000), mtime=now + i)

    elif attack_type == "suspicious_temp_exec":
        for i in range(random.randint(30, 200)):
            ext = random.choice(["exe","bat","ps1","cmd","vbs"])
            add(random.choice(TEMP_PATHS), f"tmpx_{i}.{ext}", ext,
                is_hidden=(random.random() < 0.5),
                size=random.randint(1024, 10_000_000), mtime=now + i)

    elif attack_type == "exec_proliferation":
        for i in range(random.randint(300, 800)):
            ext = random.choice(EXEC_EXTS)
            add(random.choice(USER_PATHS + SUSP_PATHS), f"exec_{i}.{ext}", ext,
                size=random.randint(1024, 5_000_000),
                crtime=now + i // 10, mtime=now + i // 10)

    elif attack_type == "high_orphan":
        for i in range(random.randint(30, 200)):
            ext = random.choice(["exe","dll","sys"])
            add(random.choice(SYS_PATHS), f"orphan_{i}.{ext}", ext,
                size=random.randint(1024, 5_000_000),
                is_orphan=True, mtime=now + i)

    elif attack_type == "abnormal_filesystem":
        for r in recs:
            r["cluster_size"] = random.choice([65536, 131072, 32768])
        for i in range(random.randint(10, 50)):
            add(random.choice(TEMP_PATHS), f"abn_{i}.exe", "exe",
                size=random.randint(1024, 5_000_000), mtime=now + i)

    elif attack_type == "timestamp_stomping":
        epoch_zero = random.choice([0, 1, 631_152_000])
        targets = random.sample(recs, min(len(recs) // 2, 200))
        for r in targets:
            r["crtime"] = epoch_zero
            r["mtime"]  = epoch_zero
            r["atime"]  = epoch_zero
            r["ctime"]  = epoch_zero
        for i in range(random.randint(10, 50)):
            add(random.choice(TEMP_PATHS), f"stomp_{i}.exe", "exe",
                size=random.randint(1024, 5_000_000), crtime=epoch_zero, mtime=epoch_zero)

    return recs


# ─── CSV helpers ─────────────────────────────────────────────────────────────

def _get_feature_names() -> List[str]:
    fv_path = os.path.join(DISK_DIR, "features", "disk_feature_vector.json")
    with open(fv_path) as f:
        return list(json.load(f).keys())

FEATURE_NAMES: List[str] = []   # populated at runtime


def _to_row(case_id: int, label: str, vector: Dict) -> Dict:
    row: Dict = {"case_id": case_id, "source_tool": "tsk", "label": label}
    for k in FEATURE_NAMES:
        row[k] = vector.get(k)
    return row


def write_csv(rows: List[Dict], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if not rows:
        return
    cols = ["case_id", "source_tool", "label"] + FEATURE_NAMES
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    global FEATURE_NAMES

    ap = argparse.ArgumentParser()
    ap.add_argument("--safe",       type=int, default=1200)
    ap.add_argument("--malicious",  type=int, default=400)
    ap.add_argument("--seed",       type=int, default=42)
    ap.add_argument("--train-csv",  default=TRAIN_CSV)
    ap.add_argument("--test-csv",   default=TEST_CSV)
    args = ap.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)

    FEATURE_NAMES = _get_feature_names()
    builder       = DiskFeatureBuilder()

    print("=" * 56)
    print("  Disk AI — Dataset Builder")
    print("=" * 56)
    print(f"  SAFE cases      : {args.safe}")
    print(f"  MALICIOUS cases : {args.malicious}")
    print(f"  Features        : {len(FEATURE_NAMES)}")
    print()

    t_start = time.time()

    # ── SAFE ──────────────────────────────────────────────────────────────────
    print("[INFO] Generating SAFE cases ...")
    safe_rows: List[Dict] = []
    t0 = time.time()
    for i in range(1, args.safe + 1):
        profile = PROFILES[(i - 1) % len(PROFILES)]
        recs    = generate_safe_records(profile, seed=args.seed + i)
        vec     = builder._build(recs)
        safe_rows.append(_to_row(i, "SAFE", vec))

        if i % 100 == 0:
            elapsed = time.time() - t0
            rate    = i / elapsed
            eta     = (args.safe - i) / rate if rate > 0 else 0
            print(f"  [{i:>5}/{args.safe}] {profile:<18}  "
                  f"recs={len(recs):>4}  "
                  f"files={int(vec.get('total_files',0)):>6,}  "
                  f"ETA={eta:.0f}s")

    t_safe = time.time() - t0
    print(f"[INFO] {len(safe_rows)} SAFE cases in {t_safe:.1f}s\n")

    # ── MALICIOUS ─────────────────────────────────────────────────────────────
    print("[INFO] Generating MALICIOUS cases ...")
    mal_rows: List[Dict] = []
    t0 = time.time()
    for i in range(args.malicious):
        case_id  = args.safe + 1 + i
        attack   = ATTACK_TYPES[i % len(ATTACK_TYPES)]
        recs     = generate_malicious_records(attack, seed=args.seed + case_id)
        vec      = builder._build(recs)
        mal_rows.append(_to_row(case_id, "MALICIOUS", vec))

        if (i + 1) % 50 == 0:
            dr = vec.get("deletion_ratio", 0)
            rs = vec.get("overall_disk_risk_score", 0)
            print(f"  [{i+1:>4}/{args.malicious}] {attack:<26}  "
                  f"del={dr:.3f}  risk={rs:.0f}")

    t_mal = time.time() - t0
    print(f"[INFO] {len(mal_rows)} MALICIOUS cases in {t_mal:.1f}s\n")

    # ── Write CSVs ────────────────────────────────────────────────────────────
    write_csv(safe_rows, args.train_csv)
    print(f"[INFO] Training CSV : {args.train_csv}  ({len(safe_rows)} rows)")

    all_test = safe_rows + mal_rows
    random.shuffle(all_test)
    write_csv(all_test, args.test_csv)
    print(f"[INFO] Test CSV     : {args.test_csv}  ({len(all_test)} rows)")

    total = time.time() - t_start
    print()
    print("=" * 56)
    print("  Dataset Summary")
    print("=" * 56)
    print(f"  SAFE cases      : {len(safe_rows)}")
    print(f"  MALICIOUS cases : {len(mal_rows)}")
    print(f"  Total           : {len(safe_rows)+len(mal_rows)}")
    print(f"  Features/case   : {len(FEATURE_NAMES)}")
    print(f"  Total time      : {total:.1f}s")
    print("=" * 56)


if __name__ == "__main__":
    main()
