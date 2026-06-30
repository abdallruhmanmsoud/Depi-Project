"""
Privilege Feature Extractor
============================
Extracts security privilege intelligence from normalized privilege data.

DFIR Rationale:
  - SeDebugPrivilege enables process memory access (Mimikatz, injection)
  - SeTcbPrivilege allows acting as OS (token impersonation)
  - SeLoadDriverPrivilege enables loading kernel drivers (rootkits)
  - SeBackupPrivilege enables reading any file (credential theft)
  - SeImpersonatePrivilege enables token impersonation (potato attacks)
  - Non-system processes with high-risk privileges indicate compromise
  - Enabled vs Present ratio reveals active exploitation vs latent risk
  - Privilege distribution across processes reveals attack scope
"""

from collections import Counter


# ── High-risk privileges for DFIR ───────────────────────────────────────────

HIGH_RISK_PRIVILEGES = {
    "SeDebugPrivilege",
    "SeTcbPrivilege",
    "SeLoadDriverPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeCreateTokenPrivilege",
    "SeSecurityPrivilege",
}

# Processes that legitimately hold high privileges
KNOWN_PRIVILEGED = {
    "system", "lsass.exe", "services.exe", "svchost.exe",
    "wininit.exe", "csrss.exe", "smss.exe", "winlogon.exe",
    "lsaiso.exe",
}


class PrivilegeFeatureExtractor:

    def extract(self, privileges: list) -> dict:

        if not privileges:
            return self._empty_features()

        total = len(privileges)
        enabled_count = 0
        present_count = 0
        default_count = 0

        # ── Per-privilege counters ──
        debug_total = 0
        debug_enabled = 0
        tcb_total = 0
        tcb_enabled = 0
        load_driver_total = 0
        load_driver_enabled = 0
        backup_total = 0
        backup_enabled = 0
        impersonate_total = 0
        impersonate_enabled = 0
        create_token_total = 0
        create_token_enabled = 0
        security_total = 0
        security_enabled = 0

        high_risk_total = 0
        high_risk_enabled = 0

        # ── Per-process tracking ──
        procs_with_debug = set()
        procs_with_high_risk_enabled = set()
        priv_per_process = Counter()
        enabled_per_process = Counter()
        high_risk_per_process = Counter()

        suspicious_procs_with_high_priv = set()

        for entry in privileges:
            pid = entry["pid"]
            proc = entry.get("process", "").lower()
            priv_name = entry.get("privilege", "")
            is_enabled = entry.get("enabled", False)
            is_present = entry.get("present", False)
            is_default = entry.get("default", False)

            priv_per_process[pid] += 1

            if is_enabled:
                enabled_count += 1
                enabled_per_process[pid] += 1
            if is_present:
                present_count += 1
            if is_default:
                default_count += 1

            # ── High-risk privilege tracking ──
            if priv_name in HIGH_RISK_PRIVILEGES:
                high_risk_total += 1
                high_risk_per_process[pid] += 1

                if is_enabled:
                    high_risk_enabled += 1
                    procs_with_high_risk_enabled.add(pid)

                    # Non-system process with enabled high-risk privilege
                    if proc not in KNOWN_PRIVILEGED:
                        suspicious_procs_with_high_priv.add(pid)

            # ── Individual privilege counters ──
            if priv_name == "SeDebugPrivilege":
                debug_total += 1
                if is_enabled:
                    debug_enabled += 1
                    procs_with_debug.add(pid)
            elif priv_name == "SeTcbPrivilege":
                tcb_total += 1
                if is_enabled:
                    tcb_enabled += 1
            elif priv_name == "SeLoadDriverPrivilege":
                load_driver_total += 1
                if is_enabled:
                    load_driver_enabled += 1
            elif priv_name == "SeBackupPrivilege":
                backup_total += 1
                if is_enabled:
                    backup_enabled += 1
            elif priv_name == "SeImpersonatePrivilege":
                impersonate_total += 1
                if is_enabled:
                    impersonate_enabled += 1
            elif priv_name == "SeCreateTokenPrivilege":
                create_token_total += 1
                if is_enabled:
                    create_token_enabled += 1
            elif priv_name == "SeSecurityPrivilege":
                security_total += 1
                if is_enabled:
                    security_enabled += 1

        # ── Per-process statistics ──
        proc_counts = list(priv_per_process.values())
        unique_procs = len(priv_per_process)
        avg_priv_per_proc = sum(proc_counts) / unique_procs if unique_procs > 0 else 0.0
        max_priv_per_proc = max(proc_counts) if proc_counts else 0

        enabled_ratio = enabled_count / total if total > 0 else 0.0
        high_risk_enabled_ratio = high_risk_enabled / high_risk_total if high_risk_total > 0 else 0.0

        return {
            # ── Aggregate ──
            "priv_total_entries":                   total,
            "priv_unique_process_count":             unique_procs,
            "priv_enabled_count":                    enabled_count,
            "priv_present_count":                    present_count,
            "priv_default_count":                    default_count,
            "priv_enabled_ratio":                    round(enabled_ratio, 4),

            # ── Critical privilege counts ──
            "priv_debug_total":                      debug_total,
            "priv_debug_enabled":                    debug_enabled,
            "priv_debug_enabled_proc_count":         len(procs_with_debug),
            "priv_tcb_total":                        tcb_total,
            "priv_tcb_enabled":                      tcb_enabled,
            "priv_load_driver_total":                load_driver_total,
            "priv_load_driver_enabled":              load_driver_enabled,
            "priv_backup_total":                     backup_total,
            "priv_backup_enabled":                   backup_enabled,
            "priv_impersonate_total":                impersonate_total,
            "priv_impersonate_enabled":              impersonate_enabled,
            "priv_create_token_total":               create_token_total,
            "priv_create_token_enabled":             create_token_enabled,
            "priv_security_total":                   security_total,
            "priv_security_enabled":                 security_enabled,

            # ── High-risk aggregate ──
            "priv_high_risk_total":                  high_risk_total,
            "priv_high_risk_enabled":                high_risk_enabled,
            "priv_high_risk_enabled_ratio":          round(high_risk_enabled_ratio, 4),
            "priv_high_risk_enabled_proc_count":     len(procs_with_high_risk_enabled),
            "priv_suspicious_high_priv_proc_count":  len(suspicious_procs_with_high_priv),

            # ── Per-process distribution ──
            "priv_per_process_avg":                  round(avg_priv_per_proc, 4),
            "priv_per_process_max":                  max_priv_per_proc,
        }

    def _empty_features(self) -> dict:
        keys = [
            "priv_total_entries", "priv_unique_process_count",
            "priv_enabled_count", "priv_present_count", "priv_default_count",
            "priv_enabled_ratio",
            "priv_debug_total", "priv_debug_enabled", "priv_debug_enabled_proc_count",
            "priv_tcb_total", "priv_tcb_enabled",
            "priv_load_driver_total", "priv_load_driver_enabled",
            "priv_backup_total", "priv_backup_enabled",
            "priv_impersonate_total", "priv_impersonate_enabled",
            "priv_create_token_total", "priv_create_token_enabled",
            "priv_security_total", "priv_security_enabled",
            "priv_high_risk_total", "priv_high_risk_enabled",
            "priv_high_risk_enabled_ratio", "priv_high_risk_enabled_proc_count",
            "priv_suspicious_high_priv_proc_count",
            "priv_per_process_avg", "priv_per_process_max",
        ]
        return {k: 0 for k in keys}
