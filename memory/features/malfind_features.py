"""
Malfind Feature Extractor
==========================
Extracts memory injection indicators from normalized malfind data.

This is the HIGHEST PRIORITY feature source for anomaly detection.

DFIR Rationale:
  - PAGE_EXECUTE_READWRITE (RWX) regions are the strongest injection signal.
    Legitimate software rarely allocates RWX memory; malware needs it for
    shellcode execution, reflective loading, and code patching.
  - Private memory + executable = injected code (not file-backed)
  - Commit charge outliers indicate large shellcode or packed payloads
  - Concentration of findings in a single process indicates targeted injection
  - Findings in system processes (lsass, svchost) are critical alerts
  - Malfind count relative to total processes gives injection density
  - PAGE_EXECUTE_READ regions may indicate ROP gadget preparation
"""

import math
from collections import Counter


CRITICAL_PROCESSES = {
    "lsass.exe", "csrss.exe", "services.exe", "svchost.exe",
    "wininit.exe", "winlogon.exe", "smss.exe", "explorer.exe",
    "spoolsv.exe", "searchindexer",
}

# Known processes that legitimately use RWX (JIT engines, AV)
KNOWN_RWX_PROCS = {
    "msmpeng.exe",       # Windows Defender
    "mpcmdrun.exe",      # Defender CLI
    "java.exe",          # Java JIT
    "javaw.exe",
    "node.exe",          # V8 JIT
    "chrome.exe",        # V8 JIT
    "msedge.exe",        # V8 JIT
    "firefox.exe",       # SpiderMonkey JIT
    "powershell.exe",    # .NET JIT
    "pwsh.exe",
    "w3wp.exe",          # IIS worker
    "dotnet.exe",        # .NET runtime
}


class MalfindFeatureExtractor:

    def extract(self, findings: list) -> dict:

        if not findings:
            return self._empty_features()

        total = len(findings)
        per_process = Counter()
        per_process_name = Counter()

        rwx_count = 0
        execute_read_count = 0
        executable_count = 0
        private_memory_count = 0
        rwx_private_count = 0
        commit_charges = []

        affected_pids = set()
        affected_procs = set()
        critical_proc_findings = 0
        non_jit_rwx_count = 0

        for entry in findings:
            pid = entry["pid"]
            proc = entry.get("process", "").lower()
            protection = entry.get("protection", "")
            is_private = entry.get("private_memory", False)
            commit = entry.get("commit_charge", 0) or 0

            per_process[pid] += 1
            per_process_name[proc] += 1
            affected_pids.add(pid)
            affected_procs.add(proc)
            commit_charges.append(commit)

            # ── Protection analysis ──
            is_rwx = "EXECUTE_READWRITE" in protection
            is_exec_read = "EXECUTE_READ" in protection and "READWRITE" not in protection
            is_executable = "EXECUTE" in protection

            if is_rwx:
                rwx_count += 1
                if is_private:
                    rwx_private_count += 1
                # Non-JIT RWX is highly suspicious
                if proc not in KNOWN_RWX_PROCS:
                    non_jit_rwx_count += 1

            if is_exec_read:
                execute_read_count += 1

            if is_executable:
                executable_count += 1

            if is_private:
                private_memory_count += 1

            # ── Critical process findings ──
            # Truncated names from Volatility (14 chars) — match prefix
            proc_clean = proc.rstrip(".")
            if any(proc_clean.startswith(cp.replace(".exe", "")) for cp in CRITICAL_PROCESSES):
                critical_proc_findings += 1

        # ── Commit charge statistics ──
        avg_commit = sum(commit_charges) / total if total > 0 else 0.0
        max_commit = max(commit_charges) if commit_charges else 0
        min_commit = min(commit_charges) if commit_charges else 0
        total_commit = sum(commit_charges)

        commit_std = 0.0
        if total > 1:
            variance = sum((c - avg_commit) ** 2 for c in commit_charges) / (total - 1)
            commit_std = math.sqrt(variance)

        # ── Concentration metrics ──
        max_findings_per_proc = max(per_process.values()) if per_process else 0
        unique_affected_procs = len(affected_procs)

        # ── Ratios ──
        rwx_ratio = rwx_count / total if total > 0 else 0.0
        private_ratio = private_memory_count / total if total > 0 else 0.0

        return {
            # ── Core counts ──
            "mf_total_findings":            total,
            "mf_unique_affected_pids":      len(affected_pids),
            "mf_unique_affected_procs":     unique_affected_procs,

            # ── Protection analysis ──
            "mf_rwx_count":                 rwx_count,
            "mf_rwx_ratio":                 round(rwx_ratio, 4),
            "mf_execute_read_count":        execute_read_count,
            "mf_executable_count":          executable_count,

            # ── Memory type ──
            "mf_private_memory_count":      private_memory_count,
            "mf_private_ratio":             round(private_ratio, 4),
            "mf_rwx_private_count":         rwx_private_count,

            # ── Anomaly indicators ──
            "mf_non_jit_rwx_count":         non_jit_rwx_count,
            "mf_critical_proc_findings":    critical_proc_findings,

            # ── Concentration ──
            "mf_max_findings_per_process":  max_findings_per_proc,

            # ── Commit charge statistics ──
            "mf_commit_total":              total_commit,
            "mf_commit_avg":                round(avg_commit, 4),
            "mf_commit_max":                max_commit,
            "mf_commit_min":                min_commit,
            "mf_commit_std":                round(commit_std, 4),
        }

    def _empty_features(self) -> dict:
        keys = [
            "mf_total_findings", "mf_unique_affected_pids",
            "mf_unique_affected_procs",
            "mf_rwx_count", "mf_rwx_ratio",
            "mf_execute_read_count", "mf_executable_count",
            "mf_private_memory_count", "mf_private_ratio",
            "mf_rwx_private_count",
            "mf_non_jit_rwx_count", "mf_critical_proc_findings",
            "mf_max_findings_per_process",
            "mf_commit_total", "mf_commit_avg", "mf_commit_max",
            "mf_commit_min", "mf_commit_std",
        ]
        return {k: 0 for k in keys}
