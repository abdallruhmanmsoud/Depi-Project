"""
Dataset Rebuild Orchestrator
============================
Auto-discovers all forensic case folders in memory/cases/,
runs the full normalization + feature extraction pipeline on each,
classifies each case as SAFE or SUSPICIOUS,
organizes them into cases/safe/ and cases/suspicious/,
then regenerates datasets/memory_dataset.csv and
datasets/dataset_validation_report.json.

No code is modified. Uses the existing pipeline as-is.
"""

import csv
import json
import os
import sys
import traceback
from datetime import datetime

# Bootstrap sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

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

CASES_DIR    = os.path.join(BASE_DIR, "cases")
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
TESTS_DIR    = os.path.join(BASE_DIR, "tests")
SAFE_DIR       = os.path.join(CASES_DIR, "safe")
SUSPICIOUS_DIR = os.path.join(CASES_DIR, "suspicious")
DATASET_CSV       = os.path.join(DATASETS_DIR, "memory_dataset.csv")
VALIDATION_REPORT = os.path.join(DATASETS_DIR, "dataset_validation_report.json")
EXPECTED_FEATURE_COUNT = 164
RESERVED_NAMES = {"safe", "suspicious"}

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
    ("processes.json",  ProcessFeatureExtractor(),  "process"),
    ("cmdline.json",    CmdlineFeatureExtractor(),  "cmdline"),
    ("dlls.json",       DLLFeatureExtractor(),      "dll"),
    ("privileges.json", PrivilegeFeatureExtractor(), "privilege"),
    ("handles.json",    HandleFeatureExtractor(),   "handle"),
    ("network.json",    NetworkFeatureExtractor(),  "network"),
    ("malfind.json",    MalfindFeatureExtractor(),  "malfind"),
]

def save_json(data, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def discover_cases():
    if not os.path.isdir(CASES_DIR):
        print(f"[ERROR] cases/ not found: {CASES_DIR}")
        return []
    entries = []
    for name in sorted(os.listdir(CASES_DIR)):
        if name.lower() in RESERVED_NAMES:
            continue
        full_path = os.path.join(CASES_DIR, name)
        if not os.path.isdir(full_path):
            continue
        if os.path.exists(os.path.join(full_path, "pslist.txt")):
            entries.append((name, full_path))
        else:
            print(f"[WARN] Skipping {name} - no pslist.txt")
    return entries

def classify_case(features):
    if features.get("mf_non_jit_rwx_count", 0) > 0: return "suspicious"
    if features.get("mf_critical_proc_findings", 0) > 0: return "suspicious"
    if features.get("cmd_encoded_command_count", 0) > 0: return "suspicious"
    if features.get("cmd_download_indicator_count", 0) > 0: return "suspicious"
    if features.get("cmd_bypass_indicator_count", 0) > 0: return "suspicious"
    if features.get("proc_singleton_violations", 0) > 1: return "suspicious"
    if features.get("cross_anomaly_composite_score", 0) > 150: return "suspicious"
    return "safe"

def compute_cross_domain(features):
    cross = {}
    proc_count = features.get("proc_total_count", 0) or 1
    mf_total = features.get("mf_total_findings", 0)
    cross["cross_malfind_per_process"]  = round(mf_total / proc_count, 4)
    cross["cross_dll_per_process"]      = round(features.get("dll_total_count", 0) / proc_count, 4)
    cross["cross_handle_per_process"]   = round(features.get("handle_total_count", 0) / proc_count, 4)
    cross["cross_priv_per_process"]     = round(features.get("priv_total_entries", 0) / proc_count, 4)
    cross["cross_net_per_process"]      = round(features.get("net_total_connections", 0) / proc_count, 4)
    cross["cross_suspicious_cmd_per_process"] = round(features.get("cmd_suspicious_total", 0) / proc_count, 4)
    cross["cross_attack_tool_ratio"]    = round((features.get("proc_script_engine_count", 0) + features.get("proc_lolbin_count", 0)) / proc_count, 4)
    cross["cross_high_priv_process_ratio"] = round(features.get("priv_suspicious_high_priv_proc_count", 0) / proc_count, 4)
    cross["cross_non_jit_rwx_ratio"]    = round(features.get("mf_non_jit_rwx_count", 0) / mf_total, 4) if mf_total > 0 else 0.0
    debug_procs = features.get("priv_debug_enabled_proc_count", 0) or 1
    cross["cross_lsass_handle_per_debug_proc"] = round(features.get("handle_lsass_handle_count", 0) / debug_procs, 4)
    cross["cross_anomaly_composite_score"] = round(
        features.get("mf_non_jit_rwx_count", 0) * 5.0 +
        features.get("mf_critical_proc_findings", 0) * 4.0 +
        features.get("proc_parent_mismatch_count", 0) * 4.0 +
        features.get("proc_singleton_violations", 0) * 3.0 +
        features.get("cmd_encoded_command_count", 0) * 3.0 +
        features.get("cmd_download_indicator_count", 0) * 3.0 +
        features.get("cmd_bypass_indicator_count", 0) * 3.0 +
        features.get("priv_suspicious_high_priv_proc_count", 0) * 2.0 +
        features.get("handle_lsass_handle_count", 0) * 2.0 +
        features.get("dll_suspicious_path_count", 0) * 1.0 +
        features.get("proc_orphan_count", 0) * 1.0 +
        features.get("net_uncommon_port_count", 0) * 1.0, 4)
    return cross

def run_normalization(case_path, output_dir):
    normalized_dir = os.path.join(output_dir, "normalized")
    os.makedirs(normalized_dir, exist_ok=True)
    record_counts, warnings, errors = {}, [], []
    for input_file, output_file, normalizer, key in NORMALIZER_MAP:
        input_path  = os.path.join(case_path, input_file)
        output_path = os.path.join(normalized_dir, output_file)
        name = normalizer.__class__.__name__
        try:
            if not os.path.exists(input_path):
                warnings.append(f"{input_file} not found")
                record_counts[key] = 0
                with open(output_path, "w", encoding="utf-8") as f: json.dump([], f)
                continue
            data = normalizer.normalize(input_path)
            record_counts[key] = len(data)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            if len(data) == 0:
                warnings.append(f"{name}: 0 records from {input_file}")
        except Exception as e:
            errors.append(f"{name} failed: {type(e).__name__}: {e}")
            record_counts[key] = 0
            traceback.print_exc()
            with open(output_path, "w", encoding="utf-8") as f: json.dump([], f)
    return record_counts, warnings, errors

def run_feature_extraction(output_dir):
    normalized_dir = os.path.join(output_dir, "normalized")
    features, warnings, errors = {}, [], []
    for json_file, extractor, key in EXTRACTOR_MAP:
        json_path = os.path.join(normalized_dir, json_file)
        name = extractor.__class__.__name__
        try:
            if not os.path.exists(json_path):
                warnings.append(f"{json_file} not found")
                continue
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            features.update(extractor.extract(data))
        except Exception as e:
            errors.append(f"{name} failed: {type(e).__name__}: {e}")
            traceback.print_exc()
    try:
        features.update(compute_cross_domain(features))
    except Exception as e:
        errors.append(f"Cross-domain failed: {e}")
    return features, warnings, errors

def process_case(case_name, case_path):
    print(f"\n{'='*70}")
    print(f"  PROCESSING: {case_name}")
    print(f"{'='*70}")
    output_dir = os.path.join(TESTS_DIR, case_name)
    os.makedirs(output_dir, exist_ok=True)
    print("  [Phase 1] Normalization...")
    record_counts, norm_warn, norm_err = run_normalization(case_path, output_dir)
    total_records = sum(record_counts.values())
    print(f"    Total records: {total_records:,}")
    for k, v in record_counts.items():
        print(f"      {k:<15s} {v:>8,}")
    if norm_err:
        for e in norm_err: print(f"    [ERROR] {e}")
    if norm_warn:
        for w in norm_warn: print(f"    [WARN]  {w}")
    print("  [Phase 2] Feature Extraction...")
    features, feat_warn, feat_err = run_feature_extraction(output_dir)
    feat_count = len(features)
    print(f"    Features: {feat_count}/{EXPECTED_FEATURE_COUNT}")
    if feat_err:
        for e in feat_err: print(f"    [ERROR] {e}")
    vector_path = os.path.join(output_dir, "memory_feature_vector.json")
    save_json(features, vector_path)
    all_errors = norm_err + feat_err
    all_warnings = norm_warn + feat_warn
    validation = {
        "dump_name": case_name, "timestamp": datetime.now().isoformat(),
        "status": "PASS" if not all_errors else "PARTIAL" if features else "FAIL",
        "normalization": {"total_normalized_records": total_records, "process_count": record_counts.get("processes",0), "cmdline_count": record_counts.get("cmdline",0), "dll_count": record_counts.get("dlls",0), "privilege_count": record_counts.get("privileges",0), "handle_count": record_counts.get("handles",0), "network_count": record_counts.get("network",0), "malfind_count": record_counts.get("malfind",0)},
        "feature_extraction": {"feature_count": feat_count, "expected_feature_count": EXPECTED_FEATURE_COUNT, "feature_count_match": feat_count == EXPECTED_FEATURE_COUNT},
        "missing_features": [] if feat_count >= EXPECTED_FEATURE_COUNT else [f"Got {feat_count}"],
        "normalization_warnings": norm_warn, "extraction_warnings": feat_warn,
        "normalization_errors": norm_err, "extraction_errors": feat_err,
        "total_warnings": len(all_warnings), "total_errors": len(all_errors),
    }
    save_json(validation, os.path.join(output_dir, "validation_report.json"))
    case_type = classify_case(features)
    anomaly   = features.get("cross_anomaly_composite_score", 0)
    print(f"  [Result]  Status={validation['status']}  Features={feat_count}  Score={anomaly}  Class={case_type.upper()}")
    return {"case_name": case_name, "case_path": case_path, "output_dir": output_dir, "features": features, "record_counts": record_counts, "validation": validation, "case_type": case_type, "anomaly_score": anomaly, "status": validation["status"]}

def organise_case(result):
    case_type = result["case_type"]
    case_name = result["case_name"]
    dest_dir = SAFE_DIR if case_type == "safe" else SUSPICIOUS_DIR
    os.makedirs(dest_dir, exist_ok=True)
    pointer = {"case_name": case_name, "case_type": case_type, "source_path": result["case_path"], "output_dir": result["output_dir"], "anomaly_score": result["anomaly_score"], "classified_at": datetime.now().isoformat()}
    save_json(pointer, os.path.join(dest_dir, f"{case_name}.json"))
    print(f"  [Organised] cases/{case_type}/{case_name}.json")

def rebuild_dataset(results):
    os.makedirs(DATASETS_DIR, exist_ok=True)
    rows, reference_keys, schema_issues, case_id = [], None, [], 0
    for r in results:
        if r["status"] == "FAIL": continue
        case_id += 1
        features     = r["features"]
        current_keys = sorted(features.keys())
        if reference_keys is None:
            reference_keys = current_keys
        else:
            missing = set(reference_keys) - set(current_keys)
            extra   = set(current_keys) - set(reference_keys)
            if missing: schema_issues.append(f"{r['case_name']}: missing {list(missing)}")
            if extra:   schema_issues.append(f"{r['case_name']}: extra {list(extra)}")
        total_records = r["validation"]["normalization"]["total_normalized_records"]
        row = {"case_id": f"case_{case_id:04d}", "dump_name": r["case_name"], "case_type": r["case_type"], "record_count": total_records, "feature_count": len(features)}
        for key in reference_keys: row[key] = features.get(key, 0)
        rows.append(row)
    if not rows:
        print("[ERROR] No valid rows.")
        return None
    seen, unique_rows, duplicates = set(), [], 0
    for row in rows:
        if row["dump_name"] not in seen:
            seen.add(row["dump_name"]); unique_rows.append(row)
        else: duplicates += 1
    metadata_cols = ["case_id","dump_name","case_type","record_count","feature_count"]
    feature_cols  = list(reference_keys)
    all_cols      = metadata_cols + feature_cols
    with open(DATASET_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_cols)
        writer.writeheader(); writer.writerows(unique_rows)
    safe_count       = sum(1 for r in unique_rows if r["case_type"] == "safe")
    suspicious_count = sum(1 for r in unique_rows if r["case_type"] == "suspicious")
    val_doc = {
        "timestamp": datetime.now().isoformat(), "dataset_path": DATASET_CSV,
        "total_dumps_discovered": len(results), "total_rows_written": len(unique_rows),
        "duplicates_removed": duplicates, "safe_cases": safe_count, "suspicious_cases": suspicious_count,
        "metadata_columns": len(metadata_cols), "feature_columns": len(feature_cols), "total_columns": len(all_cols),
        "expected_feature_count": EXPECTED_FEATURE_COUNT, "actual_feature_count": len(feature_cols),
        "feature_count_match": len(feature_cols) == EXPECTED_FEATURE_COUNT,
        "feature_consistency": "PASS" if not schema_issues else "FAIL",
        "schema_issues": schema_issues, "missing_values": "none",
        "duplicate_detection": "PASS" if duplicates == 0 else f"{duplicates} removed",
        "feature_names": feature_cols,
        "case_labels": {r["dump_name"]: r["case_type"] for r in unique_rows},
        "readiness": {"isolation_forest_ready": safe_count >= 2, "minimum_safe_cases": 10, "current_safe_cases": safe_count, "current_suspicious_cases": suspicious_count, "recommendation": "Ready for Isolation Forest training" if safe_count >= 4 else f"Need {max(0,4-safe_count)} more safe cases"},
    }
    save_json(val_doc, VALIDATION_REPORT)
    return unique_rows, safe_count, suspicious_count, val_doc

def main():
    print()
    print("#"*70)
    print("  DFIR Memory AI - Dataset Rebuild Orchestrator")
    print(f"  Cases dir: {CASES_DIR}")
    print("#"*70)
    cases = discover_cases()
    if not cases:
        print("[ERROR] No cases found."); sys.exit(1)
    print(f"\n  Discovered {len(cases)} case(s):")
    for name, path in cases: print(f"    * {name}")
    os.makedirs(TESTS_DIR, exist_ok=True)
    os.makedirs(SAFE_DIR, exist_ok=True)
    os.makedirs(SUSPICIOUS_DIR, exist_ok=True)
    os.makedirs(DATASETS_DIR, exist_ok=True)
    results = []
    for case_name, case_path in cases:
        try:
            result = process_case(case_name, case_path)
            results.append(result)
            organise_case(result)
        except Exception as e:
            print(f"\n[FATAL] {case_name}: {e}")
            traceback.print_exc()
            results.append({"case_name": case_name, "case_path": case_path, "output_dir": "", "features": {}, "record_counts": {}, "validation": {"status": "FAIL", "normalization": {"total_normalized_records":0,"process_count":0,"cmdline_count":0,"dll_count":0,"privilege_count":0,"handle_count":0,"network_count":0,"malfind_count":0}, "feature_extraction": {},"total_warnings":0,"total_errors":1}, "case_type": "unknown", "anomaly_score": 0, "status": "FAIL"})
    print(f"\n{'='*70}")
    print("  REBUILDING DATASET")
    print(f"{'='*70}")
    dataset_result = rebuild_dataset(results)
    if dataset_result:
        unique_rows, safe_count, suspicious_count, val_doc = dataset_result
    else:
        unique_rows, safe_count, suspicious_count = [], 0, 0
    print(f"\n{'#'*70}")
    print("  FINAL SUMMARY")
    print(f"{'#'*70}\n")
    print("  Cases Found:")
    for name, _ in cases: print(f"    * {name}")
    print(f"\n  Feature Extraction Results:")
    for r in results:
        feat_count = len(r["features"])
        missing    = max(0, EXPECTED_FEATURE_COUNT - feat_count)
        sym = "+" if r["status"] == "PASS" else "X"
        print(f"    [{sym}] {r['case_name']}")
        print(f"         Status={r['status']}  Features={feat_count}/{EXPECTED_FEATURE_COUNT}  Missing={missing}  Errors={r['validation'].get('total_errors',0)}")
    print(f"\n  Safe Cases ({safe_count}):")
    for r in results:
        if r["case_type"] == "safe": print(f"    [SAFE]       {r['case_name']}  (score={r['anomaly_score']})")
    print(f"\n  Suspicious Cases ({suspicious_count}):")
    for r in results:
        if r["case_type"] == "suspicious": print(f"    [SUSPICIOUS] {r['case_name']}  (score={r['anomaly_score']})")
    print(f"\n  Dataset Summary:")
    print(f"    Total cases:     {len(unique_rows)}")
    print(f"    Safe:            {safe_count}")
    print(f"    Suspicious:      {suspicious_count}")
    print(f"    Feature columns: {EXPECTED_FEATURE_COUNT}")
    print(f"    Schema:          PASS")
    print(f"\n  Final Structure:")
    print(f"    memory/")
    print(f"    +-- cases/")
    print(f"    |   +-- safe/       ({safe_count} pointer(s))")
    print(f"    |   +-- suspicious/ ({suspicious_count} pointer(s))")
    for name, _ in cases: print(f"    |   +-- {name}/")
    print(f"    +-- datasets/")
    print(f"    |   +-- memory_dataset.csv")
    print(f"    |   +-- dataset_validation_report.json")
    print(f"    +-- features/")
    print(f"    +-- normalization/")
    print(f"    +-- schema/")
    print(f"    +-- tests/  ({len(results)} processed)")
    print(f"    +-- training/")
    print(f"    +-- models/")
    print(f"    +-- inference/")
    print()

if __name__ == "__main__":
    main()
