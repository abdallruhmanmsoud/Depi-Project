"""
Multi-Dump Pipeline Test Runner
================================
Processes multiple Volatility output folders through the existing
Normalization + Feature Engineering pipeline and generates:
  - normalized/ JSON files
  - features/ feature vector
  - validation_report.json
  - feature_summary.json
  - comparison_report.json (across all dumps)

Does NOT modify any existing code. Uses the pipeline as-is.
"""

import json
import os
import sys
import traceback
from datetime import datetime

# ── Add parent directory to path so imports work ──
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from normalization.process_normalizer import ProcessNormalizer
from normalization.cmdline_normalizer import CmdlineNormalizer
from normalization.dll_normalizer import DLLNormalizer
from normalization.privilege_normalizer import PrivilegeNormalizer
from normalization.handle_normalizer import HandleNormalizer
from normalization.network_normalizer import NetworkNormalizer
from normalization.malfind_normalizer import MalfindNormalizer

from features.process_features import ProcessFeatureExtractor
from features.cmdline_features import CmdlineFeatureExtractor
from features.dll_features import DLLFeatureExtractor
from features.privilege_features import PrivilegeFeatureExtractor
from features.handle_features import HandleFeatureExtractor
from features.network_features import NetworkFeatureExtractor
from features.malfind_features import MalfindFeatureExtractor


# ── Configuration ───────────────────────────────────────────────────────────

DUMP_FOLDERS = [
    "WinDump_forensics_20260616_075839",
    "MemoryDump_forensics_20260616_083039",
    "Win11Dump_forensics_20260616_163431",
    "DESKTOP-88S7USO-20260616-144313_forensics_20260616_120619",
    "Windows 10 x64-043303df_runner_20260622_070714",
    "Win11Dump_runner_20260622_080128",
]

NORMALIZER_MAP = [
    ("pslist.txt",   "processes.json",  ProcessNormalizer(),   "processes"),
    ("cmdline.txt",  "cmdline.json",    CmdlineNormalizer(),   "cmdline"),
    ("dlllist.txt",  "dlls.json",       DLLNormalizer(),       "dlls"),
    ("privs.txt",    "privileges.json", PrivilegeNormalizer(), "privileges"),
    ("handles.txt",  "handles.json",    HandleNormalizer(),    "handles"),
    ("netscan.txt",  "network.json",    NetworkNormalizer(),   "network"),
    ("malfind.txt",  "malfind.json",    MalfindNormalizer(),   "malfind"),
]

EXTRACTOR_MAP = [
    ("processes.json",  ProcessFeatureExtractor(),   "process"),
    ("cmdline.json",    CmdlineFeatureExtractor(),   "cmdline"),
    ("dlls.json",       DLLFeatureExtractor(),       "dll"),
    ("privileges.json", PrivilegeFeatureExtractor(),  "privilege"),
    ("handles.json",    HandleFeatureExtractor(),     "handle"),
    ("network.json",    NetworkFeatureExtractor(),    "network"),
    ("malfind.json",    MalfindFeatureExtractor(),    "malfind"),
]

# Reference feature count from original pipeline
EXPECTED_FEATURE_COUNT = 164

# High-anomaly features to highlight in summary
ANOMALY_FEATURES = [
    "proc_orphan_count", "proc_parent_mismatch_count",
    "proc_singleton_violations", "proc_zero_thread_count",
    "proc_exited_still_in_memory", "proc_lolbin_count",
]

PROCESS_FEATURES = [
    "proc_total_count", "proc_svchost_count", "proc_powershell_count",
    "proc_cmd_count", "proc_script_engine_count", "proc_browser_count",
]

PRIVILEGE_FEATURES = [
    "priv_debug_enabled", "priv_tcb_enabled", "priv_load_driver_enabled",
    "priv_impersonate_enabled", "priv_suspicious_high_priv_proc_count",
    "priv_high_risk_enabled",
]

MALFIND_FEATURES = [
    "mf_total_findings", "mf_rwx_count", "mf_non_jit_rwx_count",
    "mf_critical_proc_findings", "mf_rwx_private_count",
    "mf_max_findings_per_process",
]


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 1: Normalization
# ═══════════════════════════════════════════════════════════════════════════

def run_normalization(dump_folder, output_dir):
    """
    Run all normalizers on a dump folder.
    Returns (record_counts, warnings, errors).
    """
    normalized_dir = os.path.join(output_dir, "normalized")
    os.makedirs(normalized_dir, exist_ok=True)

    record_counts = {}
    warnings = []
    errors = []

    for input_file, output_file, normalizer, key in NORMALIZER_MAP:
        input_path = os.path.join(dump_folder, input_file)
        output_path = os.path.join(normalized_dir, output_file)
        name = normalizer.__class__.__name__

        try:
            if not os.path.exists(input_path):
                warnings.append(f"{input_file} not found in dump folder")
                record_counts[key] = 0
                # Write empty array
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump([], f)
                continue

            data = normalizer.normalize(input_path)
            record_counts[key] = len(data)

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)

            if len(data) == 0:
                warnings.append(f"{name}: 0 records parsed from {input_file}")

        except Exception as e:
            error_msg = f"{name} failed: {type(e).__name__}: {e}"
            errors.append(error_msg)
            record_counts[key] = 0
            traceback.print_exc()
            # Write empty array so feature extraction doesn't crash
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump([], f)

    return record_counts, warnings, errors


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 2: Feature Extraction
# ═══════════════════════════════════════════════════════════════════════════

def run_feature_extraction(output_dir):
    """
    Run all feature extractors on normalized data.
    Returns (features, warnings, errors).
    """
    normalized_dir = os.path.join(output_dir, "normalized")
    features_dir = os.path.join(output_dir, "features")
    os.makedirs(features_dir, exist_ok=True)

    features = {}
    warnings = []
    errors = []

    for json_file, extractor, key in EXTRACTOR_MAP:
        json_path = os.path.join(normalized_dir, json_file)
        name = extractor.__class__.__name__

        try:
            if not os.path.exists(json_path):
                warnings.append(f"{json_file} not found for feature extraction")
                continue

            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            extracted = extractor.extract(data)
            features.update(extracted)

        except Exception as e:
            error_msg = f"{name} failed: {type(e).__name__}: {e}"
            errors.append(error_msg)
            traceback.print_exc()

    # ── Cross-domain features ──
    try:
        cross = compute_cross_domain(features)
        features.update(cross)
    except Exception as e:
        errors.append(f"Cross-domain computation failed: {e}")

    return features, warnings, errors


def compute_cross_domain(features):
    """Compute cross-domain features (same logic as memory_feature_builder)."""
    cross = {}
    proc_count = features.get("proc_total_count", 0) or 1

    mf_total = features.get("mf_total_findings", 0)
    cross["cross_malfind_per_process"] = round(mf_total / proc_count, 4)

    dll_total = features.get("dll_total_count", 0)
    cross["cross_dll_per_process"] = round(dll_total / proc_count, 4)

    handle_total = features.get("handle_total_count", 0)
    cross["cross_handle_per_process"] = round(handle_total / proc_count, 4)

    priv_total = features.get("priv_total_entries", 0)
    cross["cross_priv_per_process"] = round(priv_total / proc_count, 4)

    net_total = features.get("net_total_connections", 0)
    cross["cross_net_per_process"] = round(net_total / proc_count, 4)

    cmd_suspicious = features.get("cmd_suspicious_total", 0)
    cross["cross_suspicious_cmd_per_process"] = round(cmd_suspicious / proc_count, 4)

    script_count = features.get("proc_script_engine_count", 0)
    lolbin_count = features.get("proc_lolbin_count", 0)
    cross["cross_attack_tool_ratio"] = round(
        (script_count + lolbin_count) / proc_count, 4
    )

    high_priv_procs = features.get("priv_suspicious_high_priv_proc_count", 0)
    cross["cross_high_priv_process_ratio"] = round(
        high_priv_procs / proc_count, 4
    )

    non_jit = features.get("mf_non_jit_rwx_count", 0)
    cross["cross_non_jit_rwx_ratio"] = round(
        non_jit / mf_total, 4
    ) if mf_total > 0 else 0.0

    lsass_handles = features.get("handle_lsass_handle_count", 0)
    debug_procs = features.get("priv_debug_enabled_proc_count", 0) or 1
    cross["cross_lsass_handle_per_debug_proc"] = round(
        lsass_handles / debug_procs, 4
    )

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


# ═══════════════════════════════════════════════════════════════════════════
#  PHASE 3: Reports
# ═══════════════════════════════════════════════════════════════════════════

def generate_validation_report(dump_name, record_counts, features,
                                norm_warnings, norm_errors,
                                feat_warnings, feat_errors):
    """Generate validation_report.json for a single dump."""
    feature_count = len(features)
    all_warnings = norm_warnings + feat_warnings
    all_errors = norm_errors + feat_errors

    # Check for missing features relative to expected
    missing_features = []
    if feature_count < EXPECTED_FEATURE_COUNT:
        missing_features.append(
            f"Expected {EXPECTED_FEATURE_COUNT} features, got {feature_count}"
        )

    return {
        "dump_name": dump_name,
        "timestamp": datetime.now().isoformat(),
        "status": "PASS" if not all_errors else "PARTIAL" if features else "FAIL",
        "normalization": {
            "total_normalized_records": sum(record_counts.values()),
            "process_count": record_counts.get("processes", 0),
            "cmdline_count": record_counts.get("cmdline", 0),
            "dll_count": record_counts.get("dlls", 0),
            "privilege_count": record_counts.get("privileges", 0),
            "handle_count": record_counts.get("handles", 0),
            "network_count": record_counts.get("network", 0),
            "malfind_count": record_counts.get("malfind", 0),
        },
        "feature_extraction": {
            "feature_count": feature_count,
            "expected_feature_count": EXPECTED_FEATURE_COUNT,
            "feature_count_match": feature_count == EXPECTED_FEATURE_COUNT,
        },
        "missing_features": missing_features,
        "normalization_warnings": norm_warnings,
        "extraction_warnings": feat_warnings,
        "normalization_errors": norm_errors,
        "extraction_errors": feat_errors,
        "total_warnings": len(all_warnings),
        "total_errors": len(all_errors),
    }


def generate_feature_summary(dump_name, features):
    """Generate feature_summary.json for a single dump."""

    def pick(keys):
        return {k: features.get(k, 0) for k in keys}

    return {
        "dump_name": dump_name,
        "timestamp": datetime.now().isoformat(),
        "total_feature_count": len(features),
        "anomaly_indicators": pick(ANOMALY_FEATURES),
        "process_indicators": pick(PROCESS_FEATURES),
        "privilege_indicators": pick(PRIVILEGE_FEATURES),
        "malfind_indicators": pick(MALFIND_FEATURES),
        "cross_domain": {
            "anomaly_composite_score": features.get("cross_anomaly_composite_score", 0),
            "malfind_per_process": features.get("cross_malfind_per_process", 0),
            "dll_per_process": features.get("cross_dll_per_process", 0),
            "handle_per_process": features.get("cross_handle_per_process", 0),
            "non_jit_rwx_ratio": features.get("cross_non_jit_rwx_ratio", 0),
            "attack_tool_ratio": features.get("cross_attack_tool_ratio", 0),
            "high_priv_process_ratio": features.get("cross_high_priv_process_ratio", 0),
        },
        "memory_profile": {
            "total_processes": features.get("proc_total_count", 0),
            "total_dlls": features.get("dll_total_count", 0),
            "total_handles": features.get("handle_total_count", 0),
            "total_privileges": features.get("priv_total_entries", 0),
            "total_connections": features.get("net_total_connections", 0),
            "total_malfind": features.get("mf_total_findings", 0),
            "svchost_count": features.get("proc_svchost_count", 0),
            "debug_priv_enabled": features.get("priv_debug_enabled", 0),
            "rwx_regions": features.get("mf_rwx_count", 0),
            "external_connections": features.get("net_external_count", 0),
        },
    }


def generate_comparison_report(results):
    """Generate comparison_report.json comparing ALL dumps."""
    names = sorted(results.keys())
    if len(names) < 2:
        return {"error": "Need at least 2 dumps to compare"}

    # ── Per-dump summary ──
    summary = {}
    for name in names:
        feat = results[name]["features"]
        summary[name] = {
            "feature_count": len(feat),
            "process_count": feat.get("proc_total_count", 0),
            "anomaly_score": feat.get("cross_anomaly_composite_score", 0),
            "malfind_count": feat.get("mf_total_findings", 0),
            "non_jit_rwx": feat.get("mf_non_jit_rwx_count", 0),
            "network_connections": feat.get("net_total_connections", 0),
        }

    # ── Risk ranking ──
    ranked = sorted(
        names,
        key=lambda n: results[n]["features"].get("cross_anomaly_composite_score", 0),
        reverse=True,
    )
    risk_ranking = {
        name: {
            "rank": i + 1,
            "score": results[name]["features"].get("cross_anomaly_composite_score", 0),
        }
        for i, name in enumerate(ranked)
    }

    # ── Feature consistency ──
    all_feature_sets = [sorted(results[n]["features"].keys()) for n in names]
    schemas_match = all(s == all_feature_sets[0] for s in all_feature_sets)
    feature_counts = {n: len(results[n]["features"]) for n in names}

    # ── Category comparisons across all dumps ──
    def compare_keys(keys):
        comp = {}
        for k in keys:
            comp[k] = {}
            for name in names:
                comp[k][name] = results[name]["features"].get(k, 0)
        return comp

    # ── Top differences: max spread per feature ──
    all_keys = sorted(all_feature_sets[0]) if all_feature_sets else []
    spreads = {}
    for key in all_keys:
        vals = [results[n]["features"].get(key, 0) for n in names]
        if all(isinstance(v, (int, float)) for v in vals):
            spread = max(vals) - min(vals)
            spreads[key] = round(spread, 4)

    sorted_spreads = sorted(spreads.items(), key=lambda x: abs(x[1]), reverse=True)
    top_differences = {}
    for key, spread in sorted_spreads[:25]:
        top_differences[key] = {
            "spread": spread,
        }
        for name in names:
            top_differences[key][name] = results[name]["features"].get(key, 0)

    return {
        "timestamp": datetime.now().isoformat(),
        "dumps_compared": names,
        "dump_count": len(names),
        "summary": summary,
        "risk_ranking": risk_ranking,
        "highest_risk": ranked[0],
        "lowest_risk": ranked[-1],
        "schema_consistency": {
            "all_match": schemas_match,
            "feature_counts": feature_counts,
        },
        "top_25_feature_spreads": top_differences,
        "process_comparison": compare_keys(PROCESS_FEATURES),
        "privilege_comparison": compare_keys(PRIVILEGE_FEATURES),
        "malfind_comparison": compare_keys(MALFIND_FEATURES),
        "anomaly_comparison": compare_keys(ANOMALY_FEATURES),
        "cross_domain_comparison": compare_keys([
            "cross_anomaly_composite_score",
            "cross_malfind_per_process",
            "cross_non_jit_rwx_ratio",
            "cross_attack_tool_ratio",
            "cross_high_priv_process_ratio",
            "cross_dll_per_process",
            "cross_handle_per_process",
        ]),
        "network_comparison": compare_keys([
            "net_total_connections",
            "net_external_count",
            "net_established_count",
            "net_listening_count",
            "net_uncommon_port_count",
        ]),
        "handle_comparison": compare_keys([
            "handle_total_count",
            "handle_lsass_handle_count",
            "handle_persistence_key_count",
            "handle_cross_process_count",
        ]),
    }


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def save_json(data, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def process_dump(dump_name, base_dir, tests_dir):
    """Process a single dump through the full pipeline."""
    print()
    print("=" * 70)
    print(f"  PROCESSING: {dump_name}")
    print("=" * 70)

    dump_folder = os.path.join(base_dir, dump_name)
    output_dir = os.path.join(tests_dir, dump_name)
    os.makedirs(output_dir, exist_ok=True)

    # ── Phase 1: Normalization ──
    print("\n--- Phase 1: Normalization ---")
    record_counts, norm_warnings, norm_errors = run_normalization(
        dump_folder, output_dir
    )
    print(f"\nNormalization complete: {sum(record_counts.values())} total records")
    for k, v in record_counts.items():
        print(f"  {k:<15s} {v:>8,}")

    # ── Phase 2: Feature Extraction ──
    print("\n--- Phase 2: Feature Extraction ---")
    features, feat_warnings, feat_errors = run_feature_extraction(output_dir)
    print(f"\nFeature extraction complete: {len(features)} features")

    # ── Phase 3: Save outputs ──
    print("\n--- Phase 3: Generating Reports ---")

    # Feature vector
    vector_path = os.path.join(output_dir, "memory_feature_vector.json")
    save_json(features, vector_path)
    print(f"  Saved: {vector_path}")

    # Validation report
    validation = generate_validation_report(
        dump_name, record_counts, features,
        norm_warnings, norm_errors, feat_warnings, feat_errors
    )
    val_path = os.path.join(output_dir, "validation_report.json")
    save_json(validation, val_path)
    print(f"  Saved: {val_path}")

    # Feature summary
    summary = generate_feature_summary(dump_name, features)
    sum_path = os.path.join(output_dir, "feature_summary.json")
    save_json(summary, sum_path)
    print(f"  Saved: {sum_path}")

    status = validation["status"]
    print(f"\n  Status: {status}")
    if norm_errors or feat_errors:
        for e in norm_errors + feat_errors:
            print(f"  [ERROR] {e}")
    if norm_warnings:
        for w in norm_warnings:
            print(f"  [WARN]  {w}")

    return {
        "features": features,
        "record_counts": record_counts,
        "validation": validation,
        "summary": summary,
    }


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    tests_dir = os.path.join(base_dir, "tests")
    os.makedirs(tests_dir, exist_ok=True)

    print()
    print("#" * 70)
    print("  DFIR Memory Pipeline - Multi-Dump Test Runner")
    print(f"  Dumps: {len(DUMP_FOLDERS)}")
    print(f"  Output: {tests_dir}")
    print("#" * 70)

    results = {}

    for dump_name in DUMP_FOLDERS:
        dump_path = os.path.join(base_dir, dump_name)
        if not os.path.isdir(dump_path):
            print(f"\n[ERROR] Dump folder not found: {dump_path}")
            continue

        result = process_dump(dump_name, base_dir, tests_dir)
        results[dump_name] = result

    # ── Comparison Report ──
    if len(results) >= 2:
        print("\n" + "=" * 70)
        print("  GENERATING COMPARISON REPORT")
        print("=" * 70)

        comparison = generate_comparison_report(results)
        comp_path = os.path.join(tests_dir, "comparison_report.json")
        save_json(comparison, comp_path)
        print(f"  Saved: {comp_path}")

        # Print summary
        print("\n  Risk Ranking:")
        ranking = comparison["risk_ranking"]
        for name in sorted(ranking, key=lambda n: ranking[n]["rank"]):
            r = ranking[name]
            print(f"    #{r['rank']}  {name}  (score: {r['score']})")
        print(f"\n    Highest Risk: {comparison['highest_risk']}")
        print(f"    Lowest Risk:  {comparison['lowest_risk']}")

    # ── Final Summary ──
    print("\n" + "#" * 70)
    print("  FINAL SUMMARY")
    print("#" * 70)

    for dump_name, result in results.items():
        v = result["validation"]
        s = result["summary"]
        n = v["normalization"]
        print(f"\n  {dump_name}:")
        print(f"    Status:      {v['status']}")
        print(f"    Processes:   {n['process_count']:>8,}")
        print(f"    DLLs:        {n['dll_count']:>8,}")
        print(f"    Handles:     {n['handle_count']:>8,}")
        print(f"    Privileges:  {n['privilege_count']:>8,}")
        print(f"    Network:     {n['network_count']:>8,}")
        print(f"    Malfind:     {n['malfind_count']:>8,}")
        print(f"    Features:    {v['feature_extraction']['feature_count']:>8}")
        print(f"    Anomaly:     {s['cross_domain']['anomaly_composite_score']:>8.1f}")
        print(f"    Warnings:    {v['total_warnings']:>8}")
        print(f"    Errors:      {v['total_errors']:>8}")

    print()


if __name__ == "__main__":
    main()
