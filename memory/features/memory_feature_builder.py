"""
Memory Feature Builder
======================
Orchestrates the entire feature engineering pipeline for a memory forensics case.

Responsibilities:
  1. Load all normalized JSON files from the normalization layer
  2. Call each domain-specific feature extractor
  3. Merge all feature dictionaries into one flat numerical vector
  4. Add cross-domain derived features
  5. Export the final feature vector as JSON
  6. Provide DataFrame-ready structure for scikit-learn

The output is a single dictionary where every value is numerical (int or float).
No strings, no nested objects, no lists — ready for Isolation Forest / One-Class SVM.

Architecture:
  normalized/*.json  -->  Feature Extractors  -->  Merged Vector  -->  Cross-Domain  -->  Export
"""

import json
import os
import sys

from features.process_features import ProcessFeatureExtractor
from features.cmdline_features import CmdlineFeatureExtractor
from features.dll_features import DLLFeatureExtractor
from features.privilege_features import PrivilegeFeatureExtractor
from features.handle_features import HandleFeatureExtractor
from features.network_features import NetworkFeatureExtractor
from features.malfind_features import MalfindFeatureExtractor


class MemoryFeatureBuilder:
    """
    Builds a consolidated numerical feature vector from all
    normalized Volatility outputs for a single memory case.
    """

    def __init__(self, normalized_dir: str = "normalized"):
        self.normalized_dir = normalized_dir

        self.process_extractor   = ProcessFeatureExtractor()
        self.cmdline_extractor   = CmdlineFeatureExtractor()
        self.dll_extractor       = DLLFeatureExtractor()
        self.privilege_extractor = PrivilegeFeatureExtractor()
        self.handle_extractor    = HandleFeatureExtractor()
        self.network_extractor   = NetworkFeatureExtractor()
        self.malfind_extractor   = MalfindFeatureExtractor()

    # ── Data Loading ────────────────────────────────────────────────────

    def _load_json(self, filename: str) -> list:
        """Load a normalized JSON file. Returns empty list on failure."""
        path = os.path.join(self.normalized_dir, filename)
        if not os.path.exists(path):
            print(f"[WARN] {path} not found, using empty dataset")
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(f"[INFO] Loaded {path} ({len(data)} records)")
            return data
        except Exception as e:
            print(f"[ERROR] Failed to load {path}: {e}")
            return []

    # ── Cross-Domain Features ───────────────────────────────────────────

    def _compute_cross_domain(self, features: dict) -> dict:
        """
        Compute features that span multiple data sources.
        These capture relationships that no single extractor can see.
        """
        cross = {}

        proc_count = features.get("proc_total_count", 0) or 1

        # ── Injection density: malfind findings per process ──
        mf_total = features.get("mf_total_findings", 0)
        cross["cross_malfind_per_process"] = round(mf_total / proc_count, 4)

        # ── DLL density: total DLLs per process ──
        dll_total = features.get("dll_total_count", 0)
        cross["cross_dll_per_process"] = round(dll_total / proc_count, 4)

        # ── Handle density: total handles per process ──
        handle_total = features.get("handle_total_count", 0)
        cross["cross_handle_per_process"] = round(handle_total / proc_count, 4)

        # ── Privilege density: total privileges per process ──
        priv_total = features.get("priv_total_entries", 0)
        cross["cross_priv_per_process"] = round(priv_total / proc_count, 4)

        # ── Network density: connections per process ──
        net_total = features.get("net_total_connections", 0)
        cross["cross_net_per_process"] = round(net_total / proc_count, 4)

        # ── Suspicious cmdline ratio relative to all processes ──
        cmd_suspicious = features.get("cmd_suspicious_total", 0)
        cross["cross_suspicious_cmd_per_process"] = round(cmd_suspicious / proc_count, 4)

        # ── Script engine + LOLBin concentration ──
        script_count = features.get("proc_script_engine_count", 0)
        lolbin_count = features.get("proc_lolbin_count", 0)
        cross["cross_attack_tool_ratio"] = round(
            (script_count + lolbin_count) / proc_count, 4
        )

        # ── High-risk privilege vs process count ──
        high_priv_procs = features.get("priv_suspicious_high_priv_proc_count", 0)
        cross["cross_high_priv_process_ratio"] = round(
            high_priv_procs / proc_count, 4
        )

        # ── Non-JIT RWX relative to total malfind ──
        non_jit = features.get("mf_non_jit_rwx_count", 0)
        cross["cross_non_jit_rwx_ratio"] = round(
            non_jit / mf_total, 4
        ) if mf_total > 0 else 0.0

        # ── LSASS handles per process with debug privilege ──
        lsass_handles = features.get("handle_lsass_handle_count", 0)
        debug_procs = features.get("priv_debug_enabled_proc_count", 0) or 1
        cross["cross_lsass_handle_per_debug_proc"] = round(
            lsass_handles / debug_procs, 4
        )

        # ── Overall anomaly composite score ──
        # Weighted sum of the most discriminating indicators
        anomaly_score = (
            features.get("mf_non_jit_rwx_count", 0)        * 5.0 +
            features.get("mf_critical_proc_findings", 0)    * 4.0 +
            features.get("proc_parent_mismatch_count", 0)   * 4.0 +
            features.get("proc_singleton_violations", 0)    * 3.0 +
            features.get("cmd_encoded_command_count", 0)     * 3.0 +
            features.get("cmd_download_indicator_count", 0)  * 3.0 +
            features.get("cmd_bypass_indicator_count", 0)    * 3.0 +
            features.get("priv_suspicious_high_priv_proc_count", 0) * 2.0 +
            features.get("handle_lsass_handle_count", 0)     * 2.0 +
            features.get("dll_suspicious_path_count", 0)     * 1.0 +
            features.get("proc_orphan_count", 0)             * 1.0 +
            features.get("net_uncommon_port_count", 0)       * 1.0
        )
        cross["cross_anomaly_composite_score"] = round(anomaly_score, 4)

        return cross

    # ── Main Build Pipeline ─────────────────────────────────────────────

    def build(self) -> dict:
        """
        Execute the full feature engineering pipeline.
        Returns a flat dictionary of numerical features.
        """
        print("=" * 60)
        print("  Memory Feature Engineering Pipeline")
        print("=" * 60)
        print()

        # ── Step 1: Load all normalized data ──
        processes  = self._load_json("processes.json")
        cmdlines   = self._load_json("cmdline.json")
        dlls       = self._load_json("dlls.json")
        privileges = self._load_json("privileges.json")
        handles    = self._load_json("handles.json")
        network    = self._load_json("network.json")
        malfind    = self._load_json("malfind.json")
        print()

        # ── Step 2: Extract domain features ──
        print("[INFO] Extracting process features...")
        features = {}
        features.update(self.process_extractor.extract(processes))

        print("[INFO] Extracting cmdline features...")
        features.update(self.cmdline_extractor.extract(cmdlines))

        print("[INFO] Extracting DLL features...")
        features.update(self.dll_extractor.extract(dlls))

        print("[INFO] Extracting privilege features...")
        features.update(self.privilege_extractor.extract(privileges))

        print("[INFO] Extracting handle features...")
        features.update(self.handle_extractor.extract(handles))

        print("[INFO] Extracting network features...")
        features.update(self.network_extractor.extract(network))

        print("[INFO] Extracting malfind features...")
        features.update(self.malfind_extractor.extract(malfind))

        # ── Step 3: Cross-domain features ──
        print("[INFO] Computing cross-domain features...")
        features.update(self._compute_cross_domain(features))

        print()
        print(f"[INFO] Total features: {len(features)}")
        print("=" * 60)

        return features

    # ── Export Utilities ─────────────────────────────────────────────────

    def export_json(self, features: dict, output_path: str) -> None:
        """Export feature vector to JSON file."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(features, f, indent=4, ensure_ascii=False)
        print(f"[INFO] Feature vector saved to {output_path}")

    def export_csv_header(self, features: dict) -> str:
        """Return CSV header row (for dataset generation)."""
        return ",".join(features.keys())

    def export_csv_row(self, features: dict) -> str:
        """Return CSV data row (for dataset generation)."""
        return ",".join(str(v) for v in features.values())

    def get_feature_names(self, features: dict) -> list:
        """Return ordered list of feature names (for DataFrame columns)."""
        return list(features.keys())

    def get_feature_values(self, features: dict) -> list:
        """Return ordered list of feature values (for DataFrame row)."""
        return list(features.values())


# ── CLI Entry Point ─────────────────────────────────────────────────────────

def main():
    builder = MemoryFeatureBuilder(normalized_dir="normalized")
    features = builder.build()

    output_path = "features/memory_feature_vector.json"
    builder.export_json(features, output_path)

    print()
    print(f"Feature vector ({len(features)} features):")
    print("-" * 50)
    for key, value in features.items():
        print(f"  {key:<45s} {value}")


if __name__ == "__main__":
    main()
