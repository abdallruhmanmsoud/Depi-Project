"""
Handle Feature Extractor
========================
Extracts aggregation-based features from normalized handle data.

DFIR Rationale:
  - Handles to LSASS process indicate credential dumping
  - Excessive Process/Thread handles indicate injection activity
  - Token handles suggest token impersonation/manipulation
  - Registry key handles to Run/RunOnce indicate persistence
  - Mutant (mutex) handles can fingerprint known malware families
  - Handle volume per process is a density indicator for injection
  - Cross-process handles (Process type) are rare in legitimate software
"""

import math
from collections import Counter


# Handle types from Windows kernel
HANDLE_TYPES_OF_INTEREST = {
    "Process", "Thread", "File", "Key", "Token",
    "Mutant", "Event", "Section", "Directory",
    "ALPC Port", "Semaphore", "Timer",
}

# Registry paths associated with persistence
PERSISTENCE_PATHS = [
    "\\registry\\machine\\software\\microsoft\\windows\\currentversion\\run",
    "\\registry\\user\\",
    "currentversion\\run",
    "currentversion\\runonce",
    "\\services\\",
    "\\policies\\explorer\\run",
    "winlogon\\",
]

LSASS_INDICATORS = [
    "lsass",
    "lsaiso",
]


class HandleFeatureExtractor:

    def extract(self, handles: list) -> dict:

        if not handles:
            return self._empty_features()

        total = len(handles)

        # ── Type counters ──
        type_counter = Counter()
        per_process = Counter()

        # ── Specific indicators ──
        lsass_handle_count = 0
        cross_process_handles = 0
        persistence_key_count = 0
        mutant_unique_names = set()
        token_handle_count = 0
        section_handle_count = 0

        # ── Per-process tracking ──
        process_handle_procs = set()  # PIDs that hold Process-type handles

        for h in handles:
            pid = h["pid"]
            htype = h.get("type", "")
            name = (h.get("name") or "").lower()

            per_process[pid] += 1
            type_counter[htype] += 1

            # ── LSASS handle detection ──
            if any(ind in name for ind in LSASS_INDICATORS):
                lsass_handle_count += 1

            # ── Cross-process handle detection ──
            if htype == "Process" and "pid" in name.lower():
                cross_process_handles += 1
                process_handle_procs.add(pid)

            # ── Persistence registry keys ──
            if htype == "Key":
                if any(p in name for p in PERSISTENCE_PATHS):
                    persistence_key_count += 1

            # ── Mutant/Mutex tracking ──
            if htype == "Mutant" and name and name != "-":
                mutant_unique_names.add(name)

            # ── Token handles ──
            if htype == "Token":
                token_handle_count += 1

            # ── Section handles (shared memory, can be injection vector) ──
            if htype == "Section":
                section_handle_count += 1

        # ── Per-process statistics ──
        counts = list(per_process.values())
        unique_procs = len(per_process)
        avg_handles = sum(counts) / unique_procs if unique_procs > 0 else 0.0
        max_handles = max(counts) if counts else 0
        min_handles = min(counts) if counts else 0

        handle_std = 0.0
        if len(counts) > 1:
            variance = sum((c - avg_handles) ** 2 for c in counts) / (len(counts) - 1)
            handle_std = math.sqrt(variance)

        # ── Type distribution ──
        file_count = type_counter.get("File", 0)
        process_count = type_counter.get("Process", 0)
        thread_count = type_counter.get("Thread", 0)
        key_count = type_counter.get("Key", 0)
        event_count = type_counter.get("Event", 0)
        mutant_count = type_counter.get("Mutant", 0)
        directory_count = type_counter.get("Directory", 0)
        alpc_count = type_counter.get("ALPC Port", 0)
        semaphore_count = type_counter.get("Semaphore", 0)

        # ── Ratios ──
        file_ratio = file_count / total if total > 0 else 0.0
        process_ratio = process_count / total if total > 0 else 0.0
        key_ratio = key_count / total if total > 0 else 0.0
        unique_types = len(type_counter)

        return {
            # ── Aggregate ──
            "handle_total_count":               total,
            "handle_unique_process_count":       unique_procs,
            "handle_unique_type_count":          unique_types,

            # ── Type distribution ──
            "handle_file_count":                file_count,
            "handle_process_count":             process_count,
            "handle_thread_count":              thread_count,
            "handle_key_count":                 key_count,
            "handle_token_count":               token_handle_count,
            "handle_event_count":               event_count,
            "handle_mutant_count":              mutant_count,
            "handle_section_count":             section_handle_count,
            "handle_directory_count":           directory_count,
            "handle_alpc_count":                alpc_count,
            "handle_semaphore_count":           semaphore_count,

            # ── Ratios ──
            "handle_file_ratio":                round(file_ratio, 4),
            "handle_process_ratio":             round(process_ratio, 4),
            "handle_key_ratio":                 round(key_ratio, 4),

            # ── Security indicators ──
            "handle_lsass_handle_count":         lsass_handle_count,
            "handle_cross_process_count":        cross_process_handles,
            "handle_cross_process_proc_count":   len(process_handle_procs),
            "handle_persistence_key_count":      persistence_key_count,
            "handle_unique_mutant_count":         len(mutant_unique_names),

            # ── Per-process statistics ──
            "handle_per_process_avg":            round(avg_handles, 4),
            "handle_per_process_max":            max_handles,
            "handle_per_process_min":            min_handles,
            "handle_per_process_std":            round(handle_std, 4),
        }

    def _empty_features(self) -> dict:
        keys = [
            "handle_total_count", "handle_unique_process_count",
            "handle_unique_type_count",
            "handle_file_count", "handle_process_count",
            "handle_thread_count", "handle_key_count",
            "handle_token_count", "handle_event_count",
            "handle_mutant_count", "handle_section_count",
            "handle_directory_count", "handle_alpc_count",
            "handle_semaphore_count",
            "handle_file_ratio", "handle_process_ratio", "handle_key_ratio",
            "handle_lsass_handle_count", "handle_cross_process_count",
            "handle_cross_process_proc_count", "handle_persistence_key_count",
            "handle_unique_mutant_count",
            "handle_per_process_avg", "handle_per_process_max",
            "handle_per_process_min", "handle_per_process_std",
        ]
        return {k: 0 for k in keys}
