"""
DLL Feature Extractor
=====================
Extracts behavioral features from normalized DLL listing data.

DFIR Rationale:
  - DLLs loaded from temp, AppData, or user-writable directories indicate
    DLL side-loading or dropped payloads
  - Unnamed/pathless DLLs suggest reflective DLL injection
  - DLL count per process outliers indicate DLL injection
  - Non-standard system directory loading indicates DLL search-order hijacking
  - Entropy of DLL paths reveals diversity of load locations
  - Processes loading network-related DLLs (ws2_32, wininet, winhttp)
    that shouldn't need networking are suspicious
"""

import math
from collections import Counter


# ── Path classification ─────────────────────────────────────────────────────

SYSTEM_DIR_PREFIXES = [
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\windows\\",
    "\\systemroot\\system32",
    "\\systemroot\\",
    "\\??\\c:\\windows\\",
]

SUSPICIOUS_DIR_PATTERNS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\documents\\",
]

NETWORK_DLLS = {
    "ws2_32.dll", "wininet.dll", "winhttp.dll",
    "dnsapi.dll", "mswsock.dll", "rasapi32.dll",
    "urlmon.dll", "netapi32.dll",
}

CRYPTO_DLLS = {
    "bcrypt.dll", "ncrypt.dll", "crypt32.dll",
    "cryptsp.dll", "cryptbase.dll",
}

SECURITY_DLLS = {
    "amsi.dll", "sspicli.dll", "sspisrv.dll",
    "wdigest.dll", "kerberos.dll", "msv1_0.dll",
    "tspkg.dll", "pku2u.dll", "cloudap.dll",
}


class DLLFeatureExtractor:

    def extract(self, dlls: list) -> dict:

        if not dlls:
            return self._empty_features()

        total = len(dlls)
        per_process = Counter()
        system_count = 0
        user_dir_count = 0
        suspicious_path_count = 0
        no_name_count = 0
        no_path_count = 0
        network_dll_procs = set()
        crypto_dll_procs = set()
        security_dll_procs = set()
        path_depths = []

        for dll in dlls:
            pid = dll["pid"]
            dll_name = (dll.get("dll_name") or "").lower()
            path = (dll.get("path") or "").lower()

            per_process[pid] += 1

            # ── No name / no path (reflective injection indicator) ──
            if not dll_name or dll_name == "-":
                no_name_count += 1
            if not path or path == "-":
                no_path_count += 1
                continue

            # ── Path classification ──
            is_system = any(path.startswith(p) for p in SYSTEM_DIR_PREFIXES)
            if is_system:
                system_count += 1

            if "\\users\\" in path:
                user_dir_count += 1

            if any(pat in path for pat in SUSPICIOUS_DIR_PATTERNS):
                suspicious_path_count += 1

            # ── Path depth (number of directory levels) ──
            depth = path.count("\\")
            path_depths.append(depth)

            # ── DLL category tracking (per-process) ──
            if dll_name in NETWORK_DLLS:
                network_dll_procs.add(pid)
            if dll_name in CRYPTO_DLLS:
                crypto_dll_procs.add(pid)
            if dll_name in SECURITY_DLLS:
                security_dll_procs.add(pid)

        # ── Per-process DLL count statistics ──
        counts = list(per_process.values())
        avg_per_proc = sum(counts) / len(counts) if counts else 0.0
        max_per_proc = max(counts) if counts else 0
        min_per_proc = min(counts) if counts else 0

        dll_std = 0.0
        if len(counts) > 1:
            variance = sum((c - avg_per_proc) ** 2 for c in counts) / (len(counts) - 1)
            dll_std = math.sqrt(variance)

        # ── Ratios ──
        system_ratio = system_count / total if total > 0 else 0.0
        non_system_count = total - system_count - no_path_count
        unique_procs = len(per_process)

        # ── Path depth statistics ──
        avg_depth = sum(path_depths) / len(path_depths) if path_depths else 0.0
        max_depth = max(path_depths) if path_depths else 0

        return {
            # ── Counts ──
            "dll_total_count":              total,
            "dll_unique_process_count":     unique_procs,

            # ── Path classification ──
            "dll_system_dir_count":         system_count,
            "dll_system_dir_ratio":         round(system_ratio, 4),
            "dll_user_dir_count":           user_dir_count,
            "dll_suspicious_path_count":    suspicious_path_count,

            # ── Injection indicators ──
            "dll_no_name_count":            no_name_count,
            "dll_no_path_count":            no_path_count,

            # ── Per-process statistics ──
            "dll_per_process_avg":          round(avg_per_proc, 4),
            "dll_per_process_max":          max_per_proc,
            "dll_per_process_min":          min_per_proc,
            "dll_per_process_std":          round(dll_std, 4),

            # ── Category coverage ──
            "dll_network_dll_proc_count":   len(network_dll_procs),
            "dll_crypto_dll_proc_count":    len(crypto_dll_procs),
            "dll_security_dll_proc_count":  len(security_dll_procs),

            # ── Path structure ──
            "dll_path_depth_avg":           round(avg_depth, 4),
            "dll_path_depth_max":           max_depth,
            "dll_non_system_count":         non_system_count,
        }

    def _empty_features(self) -> dict:
        keys = [
            "dll_total_count", "dll_unique_process_count",
            "dll_system_dir_count", "dll_system_dir_ratio",
            "dll_user_dir_count", "dll_suspicious_path_count",
            "dll_no_name_count", "dll_no_path_count",
            "dll_per_process_avg", "dll_per_process_max",
            "dll_per_process_min", "dll_per_process_std",
            "dll_network_dll_proc_count", "dll_crypto_dll_proc_count",
            "dll_security_dll_proc_count",
            "dll_path_depth_avg", "dll_path_depth_max",
            "dll_non_system_count",
        ]
        return {k: 0 for k in keys}
