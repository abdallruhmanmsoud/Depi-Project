"""
Process Feature Extractor
=========================
Extracts behavioral features from normalized process listing data (pslist).

DFIR Rationale:
  - Process count anomalies indicate malware spawning or process hollowing
  - Orphaned processes (ppid not found) indicate parent PID spoofing
  - Exited processes still in memory suggest hollowed/terminated decoys
  - svchost.exe count deviations are a classic persistence indicator
  - Session distribution reveals cross-session lateral movement
  - WoW64 processes in server environments are suspicious
  - Thread count outliers indicate thread injection
  - Process name impersonation (lsass, csrss clones) is a common evasion
"""

import math
from collections import Counter


# ── Known-good Windows system processes and expected parent relationships ────
# Key = process name (lowercase), Value = expected parent name(s)
EXPECTED_PARENTS = {
    "smss.exe":         ["system"],
    "csrss.exe":        ["smss.exe"],
    "wininit.exe":      ["smss.exe"],
    "winlogon.exe":     ["smss.exe"],
    "services.exe":     ["wininit.exe"],
    "lsass.exe":        ["wininit.exe"],
    "lsaiso.exe":       ["wininit.exe"],
    "svchost.exe":      ["services.exe"],
    "taskhost.exe":     ["services.exe"],
    "taskhostw.exe":    ["services.exe"],
    "runtimebroker.":   ["svchost.exe"],
    "dllhost.exe":      ["svchost.exe"],
    "sihost.exe":       ["svchost.exe"],
}

# Processes that should be singletons (only one instance)
SINGLETON_PROCESSES = {
    "system", "smss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "lsaiso.exe", "csrss.exe",
}

# NOTE: csrss.exe can have 2 instances (session 0 and session 1),
# but more than 2 is suspicious.

SCRIPT_ENGINES = {
    "powershell.exe", "powershell_ise.exe", "pwsh.exe",
    "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "python.exe", "python3.exe", "pythonw.exe",
    "perl.exe", "ruby.exe", "node.exe",
}

BROWSER_PROCESSES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "opera.exe", "brave.exe",
}

LOLBIN_PROCESSES = {
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "wmic.exe", "cmstp.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe",
    "ieexec.exe", "control.exe", "pcalua.exe", "ftp.exe",
}

SENSITIVE_TARGETS = {
    "lsass.exe", "winlogon.exe", "csrss.exe", "services.exe",
}


class ProcessFeatureExtractor:

    def extract(self, processes: list) -> dict:

        if not processes:
            return self._empty_features()

        total = len(processes)
        pid_to_name = {}
        ppid_counter = Counter()
        name_counter = Counter()
        session_counter = Counter()
        thread_counts = []
        wow64_count = 0
        exited_count = 0
        zero_thread_count = 0
        orphan_count = 0
        parent_mismatch_count = 0
        script_engine_count = 0
        browser_count = 0
        lolbin_count = 0
        sensitive_count = 0
        unique_names = set()
        pids = set()

        # ── First pass: build PID→name map ──
        for p in processes:
            pid_to_name[p["pid"]] = p["process_name"].lower()
            pids.add(p["pid"])

        # ── Second pass: extract everything ──
        for p in processes:
            name_lower = p["process_name"].lower()
            ppid = p["ppid"]
            threads = p.get("threads", 0) or 0

            name_counter[name_lower] += 1
            ppid_counter[ppid] += 1
            unique_names.add(name_lower)
            thread_counts.append(threads)

            # Session distribution
            sid = p.get("session_id", "")
            if sid != "" and sid != "N/A":
                session_counter[str(sid)] += 1

            # WoW64
            if p.get("wow64", False):
                wow64_count += 1

            # Exited processes still in memory
            if p.get("exit_time") is not None:
                exited_count += 1

            # Zero-thread processes (suspicious — hollowed or terminated)
            if threads == 0:
                zero_thread_count += 1

            # Orphan detection (parent PID not in process list)
            if ppid != 0 and ppid not in pids:
                orphan_count += 1

            # Parent relationship validation
            if name_lower in EXPECTED_PARENTS:
                expected = EXPECTED_PARENTS[name_lower]
                actual_parent = pid_to_name.get(ppid, "")
                if actual_parent and actual_parent not in expected:
                    parent_mismatch_count += 1

            # Category counts
            if name_lower in SCRIPT_ENGINES:
                script_engine_count += 1
            if name_lower in BROWSER_PROCESSES:
                browser_count += 1
            if name_lower in LOLBIN_PROCESSES:
                lolbin_count += 1
            if name_lower in SENSITIVE_TARGETS:
                sensitive_count += 1

        # ── Derived statistics ──
        svchost_count = name_counter.get("svchost.exe", 0)
        csrss_count = name_counter.get("csrss.exe", 0)
        lsass_count = name_counter.get("lsass.exe", 0)
        conhost_count = name_counter.get("conhost.exe", 0)
        dllhost_count = name_counter.get("dllhost.exe", 0)
        powershell_count = name_counter.get("powershell.exe", 0) + name_counter.get("pwsh.exe", 0)
        cmd_count = name_counter.get("cmd.exe", 0)

        # Singleton violation: processes that should only appear once
        singleton_violations = 0
        for proc_name in SINGLETON_PROCESSES:
            count = name_counter.get(proc_name, 0)
            if proc_name == "csrss.exe":
                if count > 2:
                    singleton_violations += 1
            elif count > 1:
                singleton_violations += 1

        # Thread statistics
        avg_threads = sum(thread_counts) / total if total > 0 else 0.0
        max_threads = max(thread_counts) if thread_counts else 0
        min_threads = min(thread_counts) if thread_counts else 0

        thread_std = 0.0
        if total > 1:
            variance = sum((t - avg_threads) ** 2 for t in thread_counts) / (total - 1)
            thread_std = math.sqrt(variance)

        # Name entropy (process diversity measure)
        unique_ratio = len(unique_names) / total if total > 0 else 0.0

        # Max children from a single parent
        max_children = max(ppid_counter.values()) if ppid_counter else 0

        # Session spread
        unique_sessions = len(session_counter)

        return {
            # ── Counts ──
            "proc_total_count":             total,
            "proc_unique_name_count":       len(unique_names),
            "proc_svchost_count":           svchost_count,
            "proc_csrss_count":             csrss_count,
            "proc_lsass_count":             lsass_count,
            "proc_conhost_count":           conhost_count,
            "proc_dllhost_count":           dllhost_count,
            "proc_powershell_count":        powershell_count,
            "proc_cmd_count":               cmd_count,

            # ── Category indicators ──
            "proc_script_engine_count":     script_engine_count,
            "proc_browser_count":           browser_count,
            "proc_lolbin_count":            lolbin_count,
            "proc_sensitive_process_count": sensitive_count,

            # ── Anomaly indicators ──
            "proc_orphan_count":            orphan_count,
            "proc_parent_mismatch_count":   parent_mismatch_count,
            "proc_singleton_violations":    singleton_violations,
            "proc_exited_still_in_memory":  exited_count,
            "proc_zero_thread_count":       zero_thread_count,

            # ── Thread statistics ──
            "proc_thread_avg":              round(avg_threads, 4),
            "proc_thread_max":              max_threads,
            "proc_thread_min":              min_threads,
            "proc_thread_std":              round(thread_std, 4),

            # ── WoW64 ──
            "proc_wow64_count":             wow64_count,
            "proc_wow64_ratio":             round(wow64_count / total, 4) if total > 0 else 0.0,

            # ── Structural ──
            "proc_unique_name_ratio":       round(unique_ratio, 4),
            "proc_max_children_per_parent": max_children,
            "proc_unique_session_count":    unique_sessions,
        }

    def _empty_features(self) -> dict:
        keys = [
            "proc_total_count", "proc_unique_name_count",
            "proc_svchost_count", "proc_csrss_count", "proc_lsass_count",
            "proc_conhost_count", "proc_dllhost_count",
            "proc_powershell_count", "proc_cmd_count",
            "proc_script_engine_count", "proc_browser_count",
            "proc_lolbin_count", "proc_sensitive_process_count",
            "proc_orphan_count", "proc_parent_mismatch_count",
            "proc_singleton_violations", "proc_exited_still_in_memory",
            "proc_zero_thread_count",
            "proc_thread_avg", "proc_thread_max", "proc_thread_min",
            "proc_thread_std",
            "proc_wow64_count", "proc_wow64_ratio",
            "proc_unique_name_ratio", "proc_max_children_per_parent",
            "proc_unique_session_count",
        ]
        return {k: 0 for k in keys}
