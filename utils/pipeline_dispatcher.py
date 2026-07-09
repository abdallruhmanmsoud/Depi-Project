"""
pipeline_dispatcher.py
=======================
Dashboard → AI Pipeline Integration Layer.

This module is the ONLY file that bridges the Flask dashboard with the existing
AI pipelines.  It adapts tool output into each pipeline's required format, calls
the REAL exported functions, and returns a unified result dict to the dashboard.

=============================================================================
VERIFIED REAL APIs (do NOT rename anything here without re-reading the source)
=============================================================================

MEMORY   : memory.pipeline_test_runner.run_pipeline(dump_folder) -> {feature_vector, feature_vector_path}
           memory.inference.predict.predict(feature_vector_path) -> {case, anomaly_score, prediction, ...}
           core.mitre.mapper.MitreMapper(project_root=None).map(category, prediction_data, feature_vector, parsed_evidence)
           core.reporting.report_generator.ForensicReportGenerator(output_dir).generate(mitre_mapping, prediction_data, feature_vector, parsed_evidence, case_id)

DATABASE : database.normalization.database_normalizer.MysqlBinlogParser().parse_file(path) + render_events() → DatabaseNormalizer().normalize_file(parsed_txt_path) + .save(json_path, events)
           database.normalization.percona_normalizer.PerconaParser().parse_file(path) → PerconaNormalizer().normalize_events(events_list) → list
           database.normalization.pgaudit_normalizer.PgAuditParser().parse_file(path) → PgAuditNormalizer().normalize_events(events_list) → list
           database.prediction.predict_database.load_artifacts() → (model, scaler, feature_names)
           database.prediction.predict_database.extract_features(normalized_json_path) → dict
           database.prediction.predict_database.predict(vector, model, scaler, feature_names) → {prediction, raw_score, anomaly_score, interpretation, prediction_time_ms}
           core.mitre.mapper + core.reporting.report_generator (same as memory)

DISK     : disk.prediction.predict_disk.run_disk_prediction(input_path) -> {prediction, anomaly_score, raw_score, interpretation, prediction_time_ms, records_parsed, features_extracted, feature_vector}
           core.mitre.mapper + core.reporting.report_generator (same as memory)

BROWSER  : browser.normalization.browser_normalizer.normalize_browser_case(history_raw, bft_raw, passview_raw, case_id, source_file) -> dict
           browser.inference.predict.predict_browser_case(normalized, model_path, extractor_path) -> dict
           mitre.mapper.MitreMapper(rules_dir=None).map(category, prediction, anomaly_score, feature_vector)  ← 4 separate positional args
           reporting.browser_report_generator.BrowserReportGenerator(output_dir).generate(browser_prediction, mitre_mapping=None, case_id=None)

MALWARE  : malware.normalization.malware_normalizer.normalize_malware_case(pe_file_path, pestudio_raw, die_raw, floss_raw, case_id, features_py_path) -> dict
           malware.inference.predict.predict_malware_case(normalized, model_path, scaler_path) -> dict
           mitre.mapper.MitreMapper(rules_dir=None).map(category, prediction, anomaly_score, feature_vector)  ← same as browser
           reporting.report_generator.ForensicReportGenerator(output_dir).generate(mitre_mapping, prediction_data, feature_vector, case_id)

NETWORK  : network.inference.predict.predict_network_case(raw_tshark_csv_text, case_id, source_file) -> dict
           mitre.mapper.MitreMapper(rules_dir=None).map(category, prediction, anomaly_score, feature_vector)  ← same as browser
           reporting.report_generator.ForensicReportGenerator(output_dir).generate(mitre_mapping, prediction_data, feature_vector, case_id)

=============================================================================
NOTE on path management
=============================================================================
Each pipeline module uses absolute paths relative to its own __file__ to locate
model files — so we MUST add the right package root to sys.path before importing,
but we do NOT move or copy any model files.

Model file names (VERIFIED from disk):
  memory/models/isolation_forest.pkl           (memory predict.py uses MODEL_PATH = memory/models/isolation_forest.pkl)
  database/models/database_model.pkl           (predict_database.py)
  disk/models/disk_model.pkl                   (predict_disk.py)
  browser/model/model.pkl                      (predict_browser_case)
  malware/models/malware_rf_model.pkl          (predict_malware_case)
  malware/models/malware_scaler.pkl            (predict_malware_case)
  network/models/network_isolation_forest.pkl  (predict_network_case)
  network/models/network_scaler.pkl            (predict_network_case)
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)

# ── Absolute project root (e.g. e:\Big_Project\...\Depi-Project-main) ──────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _ensure_path(path: str) -> None:
    """Insert a path at the front of sys.path if it is not already there."""
    if path not in sys.path:
        sys.path.insert(0, path)


def _emit(emit_fn: Callable | None, msg: str) -> None:
    if emit_fn:
        emit_fn(msg)
    logger.info(msg)


def _load_module_from_file(module_name: str, file_path: str):
    """
    Load a Python module from an absolute file path using importlib.

    This bypasses sys.path entirely, preventing collisions where
    e.g. browser/inference/predict.py is shadowed by
    memory/inference/predict.py (both directories are on sys.path
    because earlier pipelines added them).
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create module spec for {file_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ═══════════════════════════════════════════════════════════════════════════════
#  Public entry point
# ═══════════════════════════════════════════════════════════════════════════════

def run(
    *,
    category: str,
    tool_id: str,
    filepath: str,
    raw_tool_output: str,
    session_id: str,
    output_dir: str,
    emit: Callable[[str], None] | None = None,
) -> dict:
    """
    Route a completed tool run through the appropriate AI pipeline.

    Parameters
    ----------
    category        : forensic category ("memory", "database", "disk",
                      "browser", "malware", "network")
    tool_id         : specific tool within the category
    filepath        : path to the uploaded file
    raw_tool_output : combined stdout/stderr text from tool_instance.run()
    session_id      : dashboard session identifier
    output_dir      : directory to write pipeline artefacts to
    emit            : callable(str) for live-streaming log lines

    Returns
    -------
    dict with keys: stage, prediction, risk_level, anomaly_score,
                    confidence, mitre_techniques, recommendations,
                    report_html_location, report_json_location, error (if any)
    """
    os.makedirs(output_dir, exist_ok=True)

    dispatch = {
        "memory":   _run_memory_pipeline,
        "database": _run_database_pipeline,
        "disk":     _run_disk_pipeline,
        "browser":  _run_browser_pipeline,
        "malware":  _run_malware_pipeline,
        "network":  _run_network_pipeline,
    }

    handler = dispatch.get(category)
    if handler is None:
        return {
            "stage": "skipped",
            "error": {"stage": "routing", "reason": f"Unknown category: {category}"},
        }

    try:
        return handler(
            tool_id=tool_id,
            filepath=filepath,
            raw_tool_output=raw_tool_output,
            session_id=session_id,
            output_dir=output_dir,
            emit=emit,
        )
    except Exception as exc:
        logger.exception("Pipeline dispatcher top-level exception — category=%s", category)
        return {
            "stage": "error",
            "error": {"stage": "dispatcher", "reason": str(exc)},
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  MEMORY PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def _run_memory_pipeline(
    *, tool_id, filepath, raw_tool_output, session_id, output_dir, emit
) -> dict:
    """
    Memory pipeline — calls the REAL functions exported by
    memory/pipeline_test_runner.py:

        run_normalization(dump_folder, output_dir)
            -> (record_counts, warnings, errors)

        run_feature_extraction(output_dir)
            -> (features_dict, warnings, errors)

    Then saves features to JSON and calls:
        memory/inference/predict.py  predict(feature_vector_path)  -> dict

    Dump folder discovery (in priority order):
      1. vol_runner_tool writes plugin .txt files to
         reports/<basename>_vol_runner/  — look there first.
      2. If the uploaded file IS a directory containing .txt files,
         use it directly.
      3. Fallback: scan the raw_tool_output for plugin headers and
         reconstruct per-plugin .txt files (last resort).
    """
    _emit(emit, "[Memory Pipeline] Starting memory forensics AI pipeline ...")

    memory_dir = os.path.join(PROJECT_ROOT, "memory")
    _ensure_path(memory_dir)
    _ensure_path(os.path.join(memory_dir, "normalization"))
    _ensure_path(os.path.join(memory_dir, "features"))

    # The NORMALIZER_MAP in pipeline_test_runner.py expects these .txt files:
    EXPECTED_PLUGIN_FILES = [
        "pslist.txt", "cmdline.txt", "dlllist.txt",
        "privs.txt", "handles.txt", "netscan.txt", "malfind.txt",
    ]

    # ── Stage 1: Locate the dump folder with per-plugin .txt files ────────────
    _emit(emit, "[Memory][Stage 1/8] Locating Volatility plugin output folder ...")

    dump_folder = None

    # Strategy A: vol_runner_tool writes to reports/<name>_vol_runner/
    if tool_id == "vol_runner":
        basename = os.path.splitext(os.path.basename(filepath))[0]
        candidate = os.path.join(PROJECT_ROOT, "reports", f"{basename}_vol_runner")
        if os.path.isdir(candidate):
            dump_folder = candidate
            _emit(emit, f"[Memory]   Found vol_runner output: {dump_folder}")
        else:
            _emit(emit, f"[Memory]   vol_runner dir not at: {candidate}")

    # Strategy B: the uploaded path is itself a directory with .txt plugin files
    if dump_folder is None and os.path.isdir(filepath):
        txt_files = [f for f in os.listdir(filepath) if f.endswith(".txt")]
        if any(f in EXPECTED_PLUGIN_FILES for f in txt_files):
            dump_folder = filepath
            _emit(emit, f"[Memory]   Using uploaded directory as dump folder: {filepath}")

    # Strategy C: check if uploaded file's parent directory has plugin files
    #   (e.g. user uploaded results.json from a vol_runner run)
    if dump_folder is None:
        parent = os.path.dirname(filepath)
        if os.path.isdir(parent):
            txt_files = [f for f in os.listdir(parent) if f.endswith(".txt")]
            if any(f in EXPECTED_PLUGIN_FILES for f in txt_files):
                dump_folder = parent
                _emit(emit, f"[Memory]   Found plugin .txt files in parent dir: {parent}")

    # Strategy D: scan reports/ for any recent vol_runner output folder
    if dump_folder is None:
        reports_dir = os.path.join(PROJECT_ROOT, "reports")
        if os.path.isdir(reports_dir):
            for d in sorted(os.listdir(reports_dir), reverse=True):
                cand = os.path.join(reports_dir, d)
                if os.path.isdir(cand):
                    txt_files = [f for f in os.listdir(cand) if f.endswith(".txt")]
                    if any(f in EXPECTED_PLUGIN_FILES for f in txt_files):
                        dump_folder = cand
                        _emit(emit, f"[Memory]   Found plugin files in reports/{d}")
                        break

    # Strategy E (last resort): reconstruct plugin .txt from raw_tool_output
    if dump_folder is None:
        _emit(emit, "[Memory]   No pre-existing plugin folder found -- reconstructing from stdout ...")
        dump_folder = os.path.join(output_dir, "vol_dump")
        os.makedirs(dump_folder, exist_ok=True)

        plugin_map = {
            "windows.pslist": "pslist", "windows.pstree": "pstree",
            "windows.cmdline": "cmdline", "windows.dlllist": "dlllist",
            "windows.privs": "privs", "windows.handles": "handles",
            "windows.netscan": "netscan", "windows.malfind": "malfind",
            "pslist": "pslist", "pstree": "pstree", "cmdline": "cmdline",
            "dlllist": "dlllist", "privs": "privs", "handles": "handles",
            "netscan": "netscan", "malfind": "malfind",
        }

        sections: dict[str, str] = {}
        cur_plugin: str | None = None
        cur_lines: list[str] = []

        for line in raw_tool_output.splitlines():
            m = re.search(r"Running plugin:\s*([\w.]+)", line, re.IGNORECASE)
            if m:
                if cur_plugin and cur_lines:
                    sections[cur_plugin] = "\n".join(cur_lines)
                cur_plugin = m.group(1).strip()
                cur_lines = []
            else:
                if cur_plugin:
                    cur_lines.append(line)
        if cur_plugin and cur_lines:
            sections[cur_plugin] = "\n".join(cur_lines)

        for vol_name, content in sections.items():
            short = plugin_map.get(vol_name)
            if short:
                with open(os.path.join(dump_folder, f"{short}.txt"), "w", encoding="utf-8") as f:
                    f.write(content)

    # Debug: show which plugin files exist
    found_files = [f for f in os.listdir(dump_folder) if f.endswith(".txt")]
    matched = [f for f in found_files if f in EXPECTED_PLUGIN_FILES]
    _emit(emit, f"[Memory][DEBUG] Dump folder: {dump_folder}")
    _emit(emit, f"[Memory][DEBUG] Total .txt files found : {len(found_files)}")
    _emit(emit, f"[Memory][DEBUG] Pipeline-relevant files: {len(matched)}  {matched}")
    if not matched:
        _emit(emit, "[Memory][WARN] No plugin .txt files found -- normalization will produce empty features.")

    # ── Stage 2: Normalization ────────────────────────────────────────────────
    _emit(emit, "[Memory][Stage 2/8] Running normalization (7 normalizers) ...")

    pipeline_output_dir = os.path.join(output_dir, "memory_pipeline")
    os.makedirs(pipeline_output_dir, exist_ok=True)

    try:
        from pipeline_test_runner import run_normalization  # type: ignore  # noqa
        record_counts, norm_warnings, norm_errors = run_normalization(
            dump_folder, pipeline_output_dir
        )
        total_records = sum(record_counts.values())
        _emit(emit, f"[Memory][DEBUG] Normalization complete: {total_records} total records")
        for key, count in record_counts.items():
            _emit(emit, f"[Memory][DEBUG]   {key:<15s} {count:>8,}")
        for w in norm_warnings:
            _emit(emit, f"[Memory][NORM WARN] {w}")
        for e in norm_errors:
            _emit(emit, f"[Memory][NORM ERROR] {e}")
    except Exception as exc:
        return _pipeline_error("memory", "normalization", str(exc))

    # ── Stage 3: Feature extraction ───────────────────────────────────────────
    _emit(emit, "[Memory][Stage 3/8] Running feature extraction (7 extractors + cross-domain) ...")

    try:
        from pipeline_test_runner import run_feature_extraction  # type: ignore  # noqa
        features, feat_warnings, feat_errors = run_feature_extraction(pipeline_output_dir)
        _emit(emit, f"[Memory][DEBUG] Feature extraction complete: {len(features)} features")
        for w in feat_warnings:
            _emit(emit, f"[Memory][FEAT WARN] {w}")
        for e in feat_errors:
            _emit(emit, f"[Memory][FEAT ERROR] {e}")

        # Show key anomaly indicators
        composite = features.get("cross_anomaly_composite_score", 0)
        _emit(emit, f"[Memory][DEBUG] Composite anomaly score: {composite}")
        _emit(emit, f"[Memory][DEBUG] proc_total_count:        {features.get('proc_total_count', 0)}")
        _emit(emit, f"[Memory][DEBUG] mf_total_findings:       {features.get('mf_total_findings', 0)}")
        _emit(emit, f"[Memory][DEBUG] mf_non_jit_rwx_count:    {features.get('mf_non_jit_rwx_count', 0)}")
    except Exception as exc:
        return _pipeline_error("memory", "feature_extraction", str(exc))

    # Save feature vector to JSON (predict.py reads from file)
    feature_vector = features  # the full dict IS the feature vector
    feature_vector_path = os.path.join(pipeline_output_dir, "memory_feature_vector.json")
    with open(feature_vector_path, "w", encoding="utf-8") as f:
        json.dump(feature_vector, f, indent=4, ensure_ascii=False)
    _emit(emit, f"[Memory][DEBUG] Feature vector saved: {feature_vector_path}")

    # ── Stage 4-5: Prediction ─────────────────────────────────────────────────
    _emit(emit, "[Memory][Stage 4/8] Loading AI model (Isolation Forest) ...")

    try:
        _ensure_path(os.path.join(memory_dir, "inference"))
        from inference.predict import predict as memory_predict  # type: ignore  # noqa
        _emit(emit, "[Memory][DEBUG] memory_predict() imported successfully")
    except ImportError as exc:
        return _pipeline_error("memory", "prediction", f"Cannot import inference.predict: {exc}")

    _emit(emit, "[Memory][Stage 5/8] Running prediction ...")

    try:
        pred_result = memory_predict(feature_vector_path)
        raw_pred_label = pred_result.get("prediction", "normal")   # "normal" or "anomalous"
        anomaly_score  = float(pred_result.get("anomaly_score", 0.0))
        prediction     = "MALICIOUS" if raw_pred_label == "anomalous" else "SAFE"
        _emit(emit, f"[Memory][DEBUG] Raw prediction label: {raw_pred_label}")
        _emit(emit, f"[Memory][DEBUG] Anomaly score:        {anomaly_score:.6f}")
        _emit(emit, f"[Memory][DEBUG] Features used:        {pred_result.get('features_used', 'N/A')}")
        _emit(emit, f"[Memory][DEBUG] Missing features:     {pred_result.get('missing_features', 'N/A')}")
        _emit(emit, f"[Memory]   Prediction: {prediction}  anomaly_score: {anomaly_score:.4f}")
    except Exception as exc:
        return _pipeline_error("memory", "prediction", str(exc))

    # Wrap raw result for core/mitre/mapper
    prediction_data = {
        "prediction":    prediction,
        "anomaly_score": anomaly_score,
        "category":      "memory",
        **pred_result,
    }

    # ── Stage 6: MITRE Mapping ────────────────────────────────────────────────
    _emit(emit, "[Memory][Stage 6/8] Running MITRE ATT&CK mapping (core mapper) ...")

    try:
        _ensure_path(os.path.join(PROJECT_ROOT, "core", "mitre"))
        from core.mitre.mapper import MitreMapper as CoreMitreMapper  # type: ignore  # noqa
        core_mapper = CoreMitreMapper(project_root=PROJECT_ROOT)
        mitre_mapping = core_mapper.map(
            category="memory",
            prediction_data=prediction_data,
            feature_vector=feature_vector,
        )
        techniques = mitre_mapping.get("techniques", [])
        risk_level = mitre_mapping.get("risk_level", "UNKNOWN")
        _emit(emit, f"[Memory][DEBUG] MITRE techniques matched: {len(techniques)}")
        _emit(emit, f"[Memory][DEBUG] Risk level:               {risk_level}")
        for t in techniques[:5]:
            tid = t.get("id", t.get("technique_id", ""))
            tname = t.get("name", t.get("technique_name", ""))
            _emit(emit, f"[Memory][DEBUG]   {tid} - {tname}")
        if len(techniques) > 5:
            _emit(emit, f"[Memory][DEBUG]   ... and {len(techniques) - 5} more")
    except Exception as exc:
        _emit(emit, f"[Memory][WARN] MITRE mapping failed: {exc} -- continuing without MITRE.")
        mitre_mapping = {"techniques": [], "risk_level": "UNKNOWN", "recommendations": []}
        techniques = []
        risk_level = "UNKNOWN"

    # ── Stage 7: Report ───────────────────────────────────────────────────────
    _emit(emit, "[Memory][Stage 7/8] Generating forensic report ...")

    report_paths = {}
    try:
        _ensure_path(os.path.join(PROJECT_ROOT, "core", "reporting"))
        from core.reporting.report_generator import ForensicReportGenerator as CoreReportGen  # type: ignore  # noqa
        report_gen = CoreReportGen(output_dir=output_dir)
        report_paths = report_gen.generate(
            mitre_mapping=mitre_mapping,
            prediction_data=prediction_data,
            feature_vector=feature_vector,
            case_id=session_id,
        )
        _emit(emit, f"[Memory]   Report HTML: {report_paths.get('html', 'N/A')}")
        _emit(emit, f"[Memory]   Report JSON: {report_paths.get('json', 'N/A')}")
    except Exception as exc:
        _emit(emit, f"[Memory][WARN] Report generation failed: {exc}")

    _emit(emit, "[Memory][Stage 8/8] Memory pipeline complete.")
    return _build_result(
        prediction=prediction,
        risk_level=risk_level,
        anomaly_score=anomaly_score,
        confidence=None,
        mitre_mapping=mitre_mapping,
        report_paths=report_paths,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  DATABASE PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def _run_database_pipeline(
    *, tool_id, filepath, raw_tool_output, session_id, output_dir, emit
) -> dict:
    """
    Database pipeline — verified against:
      database/normalization/database_normalizer.py  → DatabaseNormalizer().normalize_file(parsed_events_txt_path)
                                                       DatabaseNormalizer().save(json_path, events)
      database/normalization/percona_normalizer.py   → PerconaNormalizer().normalize_events(events_list)
      database/normalization/pgaudit_normalizer.py   → PgAuditNormalizer().normalize_events(events_list)
      database/prediction/predict_database.py        → load_artifacts(), extract_features(json_path), predict(vector, model, scaler, names)
      core/mitre/mapper.py + core/reporting/report_generator.py

    Database pipeline flow (mysqlbinlog):
      1. MysqlBinlogParser.parse_file(filepath) → raw events list
      2. render_events(events, parsed_txt_path) → writes parsed_events.txt
      3. DatabaseNormalizer().normalize_file(parsed_txt_path) → normalized events list
      4. DatabaseNormalizer().save(normalized_json_path, events) → writes JSON
      5. extract_features(normalized_json_path) → feature vector dict
      6. predict(vector, model, scaler, feature_names) → prediction dict

    Percona/pgAudit pipeline flow:
      1. PerconaParser/PgAuditParser.parse_file(filepath) → raw events list
      2. PerconaNormalizer/PgAuditNormalizer().normalize_events(raw_events) → normalized events list
      3. Save normalized list to JSON
      4. extract_features(normalized_json_path) → feature vector dict
      5. predict(...)
    """
    _emit(emit, "[Database Pipeline] Starting database forensics AI pipeline ...")

    database_dir = os.path.join(PROJECT_ROOT, "database")
    _ensure_path(database_dir)
    _ensure_path(os.path.join(database_dir, "normalization"))
    _ensure_path(os.path.join(database_dir, "prediction"))
    _ensure_path(os.path.join(database_dir, "features"))
    _ensure_path(os.path.join(database_dir, "parser"))

    # ── Stage 2+3: Parse → Normalize → Save JSON ─────────────────────────────
    _emit(emit, "[Database][Stage 2/8] Parsing and normalizing database log ...")

    os.makedirs(os.path.join(output_dir, "db_work"), exist_ok=True)
    parsed_txt_path      = os.path.join(output_dir, "db_work", "parsed_events.txt")
    normalized_json_path = os.path.join(output_dir, "normalized_events.json")

    try:
        if tool_id == "percona":
            from percona_parser import PerconaParser  # type: ignore  # noqa
            from percona_normalizer import PerconaNormalizer  # type: ignore  # noqa
            _emit(emit, "[Database]   Using Percona Toolkit parser + normalizer ...")
            parser = PerconaParser()
            raw_events = parser.parse_file(filepath)
            _emit(emit, f"[Database]   Parsed {len(raw_events)} raw events.")
            norm = PerconaNormalizer()
            normalized_events = norm.normalize_events(raw_events)
            _emit(emit, f"[Database]   Normalized {len(normalized_events)} events.")
            with open(normalized_json_path, "w", encoding="utf-8") as f:
                json.dump(normalized_events, f, indent=2, default=str)

        elif tool_id == "pgaudit":
            from pgaudit_parser import PgAuditParser  # type: ignore  # noqa
            from pgaudit_normalizer import PgAuditNormalizer  # type: ignore  # noqa
            _emit(emit, "[Database]   Using pgAudit parser + normalizer ...")
            parser = PgAuditParser()
            raw_events = parser.parse_file(filepath)
            _emit(emit, f"[Database]   Parsed {len(raw_events)} raw events.")
            norm = PgAuditNormalizer()
            normalized_events = norm.normalize_events(raw_events)
            _emit(emit, f"[Database]   Normalized {len(normalized_events)} events.")
            with open(normalized_json_path, "w", encoding="utf-8") as f:
                json.dump(normalized_events, f, indent=2, default=str)

        else:
            # mysqlbinlog (default)
            # DatabaseNormalizer.normalize_file() expects a parsed_events.txt block file,
            # NOT the raw binlog. We must:
            #   1. MysqlBinlogParser.parse_file(filepath) → raw event list
            #   2. render_events(raw_events, parsed_txt_path) → writes parsed_events.txt
            #   3. DatabaseNormalizer().normalize_file(parsed_txt_path) → normalized list
            #   4. DatabaseNormalizer().save(json_path, events) → writes JSON for extract_features()
            from mysqlbinlog_parser import MysqlBinlogParser, render_events  # type: ignore  # noqa
            from database_normalizer import DatabaseNormalizer  # type: ignore  # noqa
            _emit(emit, "[Database]   Using MySQLBinlog parser + DatabaseNormalizer ...")
            parser = MysqlBinlogParser()
            raw_events = parser.parse_file(filepath)
            _emit(emit, f"[Database]   Parsed {len(raw_events)} raw events.")
            render_events(raw_events, parsed_txt_path)
            _emit(emit, f"[Database]   Rendered parsed_events.txt -> {parsed_txt_path}")
            norm = DatabaseNormalizer()
            normalized_events = norm.normalize_file(parsed_txt_path)
            _emit(emit, f"[Database]   Normalized {len(normalized_events)} events.")
            norm.save(normalized_json_path, normalized_events)
            _emit(emit, f"[Database]   Saved normalized JSON -> {normalized_json_path}")

    except Exception as exc:
        return _pipeline_error("database", "parsing/normalization", str(exc))

    # ── Stage 4-5: Feature extraction + Prediction ────────────────────────────
    _emit(emit, "[Database][Stage 4/8] Loading AI model (Isolation Forest) ...")
    _emit(emit, "[Database][Stage 5/8] Extracting features and running prediction ...")

    try:
        from predict_database import load_artifacts, extract_features, predict as db_predict  # type: ignore  # noqa
        model, scaler, feature_names = load_artifacts()
        feature_vector = extract_features(normalized_json_path)
        pred_result = db_predict(feature_vector, model, scaler, feature_names)

        prediction    = pred_result.get("prediction", "SAFE")
        anomaly_score = float(pred_result.get("anomaly_score", 0.0))
        interpretation = pred_result.get("interpretation", "")
        _emit(emit, f"[Database]   Prediction: {prediction}  score: {anomaly_score:.4f}  ({interpretation})")
    except Exception as exc:
        return _pipeline_error("database", "prediction", str(exc))

    prediction_data = {
        "prediction":    prediction,
        "anomaly_score": anomaly_score,
        "category":      "database",
        **pred_result,
    }

    # ── Stage 6: MITRE ────────────────────────────────────────────────────────
    _emit(emit, "[Database][Stage 6/8] Running MITRE ATT&CK mapping ...")
    mitre_mapping, risk_level = _core_mitre("database", prediction_data, feature_vector, emit)

    # ── Stage 7: Report ───────────────────────────────────────────────────────
    _emit(emit, "[Database][Stage 7/8] Generating forensic report ...")
    report_paths = _core_report(
        mitre_mapping=mitre_mapping,
        prediction_data=prediction_data,
        feature_vector=feature_vector,
        output_dir=output_dir,
        case_id=session_id,
        emit=emit,
    )

    _emit(emit, "[Database][Stage 8/8] Database pipeline complete.")
    return _build_result(
        prediction=prediction,
        risk_level=risk_level,
        anomaly_score=anomaly_score,
        confidence=None,
        mitre_mapping=mitre_mapping,
        report_paths=report_paths,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  DISK PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════


# FLS line regex — matches fls output lines like:
#   r/r 4-128-1:\t$AttrDef
#   + d/d 29-144-2:\t$Deleted
#   r/- * 0:\tSomething          (deleted, no inode)
_FLS_LINE_RE = re.compile(
    r"^(?:\+*\s*)?"                      # optional depth markers
    r"[a-zA-Z\-]+/[a-zA-Z\-]+"          # type flag (r/r, d/d, -/r, r/-, etc.)
    r"\s+"
    r"(?:\d+(?:-\d+)*|\*)"              # inode or * (deleted)
    r"(?:\s+\d+)?"                       # optional extra field
    r"(?:\s*\([^)]*\))?"                 # optional (realloc)
    r":\s"                               # colon + whitespace/tab
)


def _extract_tsk_sections(
    raw_output: str, work_dir: str, emit: Callable | None
) -> None:
    """
    Extract FLS and fsstat sections from the combined dashboard output.

    The dashboard's fls_tool/tsk_tool runs ``fsstat`` then ``fls -r``
    and the output goes into a single ``raw_tool_output`` string.
    TskParser expects separate ``fls.txt``, ``fsstat.txt`` files in a
    directory.

    We identify FLS lines by the type-flag pattern and fsstat lines by
    NTFS metadata patterns, writing each to the appropriate file.
    """
    fls_lines = []
    fsstat_lines = []

    # fsstat content identifiers
    _fsstat_markers = {
        "FILE SYSTEM INFORMATION", "METADATA INFORMATION",
        "CONTENT INFORMATION", "File System Type:",
        "Volume Serial Number:", "OEM Name:",
        "First Cluster of MFT", "Size of MFT Entries",
        "Sector Size:", "Cluster Size:",
        "Total Cluster Range:", "Total Sector Range:",
        "Range:", "Root Directory:",
        "Volume Name:", "Version:",
        "Size of Index Records:",
        "$AttrDef Attribute Values:",
    }

    in_fsstat_section = False

    for line in raw_output.splitlines():
        stripped = line.rstrip()

        # Skip dashboard log lines
        if stripped.startswith("[Step ") or stripped.startswith("[Stage "):
            in_fsstat_section = False
            continue
        if stripped.startswith("$ "):  # command echo line
            if "fsstat" in stripped:
                in_fsstat_section = True
            elif "fls" in stripped:
                in_fsstat_section = False
            continue
        if stripped.startswith("Forensics Dashboard") or stripped.startswith("====="):
            continue
        if stripped.startswith("Tool   :") or stripped.startswith("File   :"):
            continue
        if stripped.startswith("Date   :") or stripped.startswith("Local file:"):
            continue
        if stripped.startswith("Validation:") or stripped.startswith("--- Analysis"):
            continue
        if stripped.startswith("FLS analysis complete") or stripped.startswith("TSK analysis complete"):
            continue

        # Check if this is an FLS line
        if _FLS_LINE_RE.match(stripped):
            fls_lines.append(stripped)
            in_fsstat_section = False
            continue

        # Check if this is a fsstat line
        if in_fsstat_section and stripped:
            fsstat_lines.append(stripped)
            continue

        # Check if line starts a fsstat section
        if any(marker in stripped for marker in _fsstat_markers):
            fsstat_lines.append(stripped)
            in_fsstat_section = True
            continue

        # Dashed separator lines often belong to fsstat
        if stripped.startswith("---") and in_fsstat_section:
            fsstat_lines.append(stripped)
            continue

    # Write all 5 expected files (even if empty) to ensure TskParser finds them.
    files_to_write = {
        "fls.txt": fls_lines,
        "fsstat.txt": fsstat_lines,
        "ils.txt": [],         # Placeholder: Add extraction logic if needed
        "bodyfile.txt": [],    # Placeholder: Add extraction logic if needed
        "timeline.txt": [],    # Placeholder: Add extraction logic if needed
    }

    for filename, lines in files_to_write.items():
        file_path = os.path.abspath(os.path.join(work_dir, filename))
        with open(file_path, "w", encoding="utf-8") as f:
            if lines:
                f.write("\n".join(lines) + "\n")
            else:
                f.write("") # Write empty file
        
        # Emit debug logs as requested
        exists = os.path.exists(file_path)
        size = os.path.getsize(file_path) if exists else 0
        _emit(emit, f"[Disk][DEBUG] Wrote {filename}:")
        _emit(emit, f"[Disk][DEBUG]   Path:   {file_path}")
        _emit(emit, f"[Disk][DEBUG]   Exists: {exists}")
        _emit(emit, f"[Disk][DEBUG]   Size:   {size} bytes")
        _emit(emit, f"[Disk][DEBUG]   Lines:  {len(lines)}")

    # Error out if required files are missing or empty
    fls_path = os.path.join(work_dir, "fls.txt")
    if not os.path.exists(fls_path) or os.path.getsize(fls_path) == 0:
        raise ValueError("Critical failure: fls.txt is missing or empty after extraction. Cannot parse disk records.")

    fsstat_path = os.path.join(work_dir, "fsstat.txt")
    if not os.path.exists(fsstat_path) or os.path.getsize(fsstat_path) == 0:
        raise ValueError("Critical failure: fsstat.txt is missing or empty after extraction. Cannot determine filesystem info.")

def _run_disk_pipeline(
    *, tool_id, filepath, raw_tool_output, session_id, output_dir, emit
) -> dict:
    """
    Disk pipeline — verified against:
      disk/prediction/predict_disk.py → run_disk_prediction(input_path) -> dict
        (handles parsing, normalization, features, model internally)
      core/mitre/mapper.py + core/reporting/report_generator.py

    run_disk_prediction() accepts a directory OR a file path (.body, .txt, .csv, .tsv).
    We pass filepath directly if it's a .txt/.body/.csv, otherwise we write the raw
    tool output to a temp file for it to parse.
    """
    _emit(emit, "[Disk Pipeline] Starting disk forensics AI pipeline ...")

    disk_dir = os.path.join(PROJECT_ROOT, "disk")
    _ensure_path(disk_dir)
    _ensure_path(os.path.join(disk_dir, "prediction"))
    _ensure_path(os.path.join(disk_dir, "parser"))
    _ensure_path(os.path.join(disk_dir, "features"))

    # ── Stage 2: Prepare input for TskParser ─────────────────────────────────
    _emit(emit, "[Disk][Stage 2/8] Preparing disk forensics input ...")

    # TskParser expects a DIRECTORY containing fls.txt, fsstat.txt, etc.
    # The dashboard gives us:
    #   - filepath: the uploaded disk image (e.g., .dd, .img)
    #   - raw_tool_output: combined stdout from fls/tsk tool (contains
    #     both fsstat and fls output interleaved with dashboard log lines)
    #
    # We extract the relevant sections and write them to a temp directory.
    tsk_work_dir = os.path.join(output_dir, "tsk_work")
    os.makedirs(tsk_work_dir, exist_ok=True)

    # Check if a directory with pre-made fls.txt/fsstat.txt already exists
    disk_input_path = filepath
    if os.path.isdir(filepath):
        tsk_work_dir = filepath
        _emit(emit, f"[Disk]   Using existing directory: {filepath}")
    else:
        # Extract FLS and fsstat sections from raw_tool_output
        _emit(emit, "[Disk]   Extracting FLS/fsstat from raw tool output ...")
        _extract_tsk_sections(raw_tool_output, tsk_work_dir, emit)

    # ── Stage 3: Parse ─────────────────────────────────────────────────────────
    _emit(emit, "[Disk][Stage 3/8] Parsing disk forensics output (TskParser) ...")

    try:
        # predict_disk.py has NO run_disk_prediction() function.
        # Its main() does parsing + normalization + features + model inline.
        # We replicate that logic here, calling the REAL exported classes.
        _ensure_path(os.path.join(disk_dir, "parser"))
        _ensure_path(os.path.join(disk_dir, "features"))
        import joblib as _jl
        import numpy as _np
        from tsk_parser import TskParser  # type: ignore  # noqa
        from disk_feature_builder import DiskFeatureBuilder  # type: ignore  # noqa
        from predict_disk import (
            _normalize_fls_records, interpret_score, get_risk_flags,
        )  # type: ignore  # noqa

        # Debug log directory contents before parsing
        dir_contents = os.listdir(tsk_work_dir)
        _emit(emit, f"[Disk][DEBUG] Directory contents of {tsk_work_dir}:")
        for filename in dir_contents:
            _emit(emit, f"[Disk][DEBUG]   - {filename}")

        parser = TskParser(root=tsk_work_dir)
        parser.parse()
        records_parsed = len(parser.fls_records)
        _emit(emit, f"[Disk][DEBUG] TskParser: {records_parsed:,} file records")

        # Normalize
        records = _normalize_fls_records(parser.fls_records, parser.fsinfo)
        _emit(emit, f"[Disk][DEBUG] Normalized: {len(records):,} records")

        # Feature extraction
        feat_builder = DiskFeatureBuilder()
        fv = feat_builder._build(records)
        _emit(emit, f"[Disk][DEBUG] Features extracted: {len(fv)}")

    except Exception as exc:
        return _pipeline_error("disk", "parsing/features", str(exc))

    # ── Stage 4-5: Model + Predict ────────────────────────────────────────────
    _emit(emit, "[Disk][Stage 4/8] Loading AI model (Isolation Forest) ...")
    _emit(emit, "[Disk][Stage 5/8] Running prediction ...")

    try:
        _models = os.path.join(disk_dir, "models")
        _model  = _jl.load(os.path.join(_models, "disk_model.pkl"))
        _scaler = _jl.load(os.path.join(_models, "disk_scaler.pkl"))
        with open(os.path.join(_models, "feature_order.json")) as _fo:
            _feat_names = json.load(_fo)["feature_order"]

        x = _np.array(
            [float(fv.get(f) or 0) for f in _feat_names],
            dtype=_np.float64,
        ).reshape(1, -1)
        x_sc = _scaler.transform(x)

        import time as _time
        t0 = _time.perf_counter()
        raw_pred = _model.predict(x_sc)[0]
        raw_score = float(_model.score_samples(x_sc)[0])
        t1 = _time.perf_counter()

        prediction     = "SAFE" if raw_pred == 1 else "MALICIOUS"
        anomaly_score  = round(-raw_score, 6)
        interpretation = interpret_score(raw_score)
        pred_time_ms   = round((t1 - t0) * 1000, 4)

        feature_vector = {k: v for k, v in fv.items()
                         if isinstance(v, (int, float, type(None)))}

        pred_result = {
            "prediction":         prediction,
            "raw_score":          round(raw_score, 6),
            "anomaly_score":      anomaly_score,
            "interpretation":     interpretation,
            "prediction_time_ms": pred_time_ms,
            "records_parsed":     records_parsed,
            "features_extracted": len(fv),
            "feature_vector":     feature_vector,
            "risk_flags":         get_risk_flags(fv),
        }

        _emit(emit, f"[Disk][DEBUG] Prediction: {prediction}  score: {anomaly_score:.4f}  ({interpretation})")
        _emit(emit, f"[Disk][DEBUG] Records parsed: {records_parsed}  features: {len(fv)}")
    except Exception as exc:
        return _pipeline_error("disk", "prediction", str(exc))

    prediction_data = {
        "prediction":    prediction,
        "anomaly_score": anomaly_score,
        "category":      "disk",
        **{k: v for k, v in pred_result.items() if k != "feature_vector"},
    }

    # ── Stage 6: MITRE ────────────────────────────────────────────────────────
    _emit(emit, "[Disk][Stage 6/8] Running MITRE ATT&CK mapping ...")
    mitre_mapping, risk_level = _core_mitre("disk", prediction_data, feature_vector, emit)

    # ── Stage 7: Report ───────────────────────────────────────────────────────
    _emit(emit, "[Disk][Stage 7/8] Generating forensic report ...")
    report_paths = _core_report(
        mitre_mapping=mitre_mapping,
        prediction_data=prediction_data,
        feature_vector=feature_vector,
        output_dir=output_dir,
        case_id=session_id,
        emit=emit,
    )

    _emit(emit, "[Disk][Stage 8/8] Disk pipeline complete.")
    return _build_result(
        prediction=prediction,
        risk_level=risk_level,
        anomaly_score=anomaly_score,
        confidence=None,
        mitre_mapping=mitre_mapping,
        report_paths=report_paths,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  BROWSER PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def _run_browser_pipeline(
    *, tool_id, filepath, raw_tool_output, session_id, output_dir, emit
) -> dict:
    """
    Browser pipeline — verified against browser/run_pipeline.py:
      browser.normalization.browser_normalizer.normalize_browser_case(history_raw, bft_raw, passview_raw, case_id, source_file)
      browser.inference.predict.predict_browser_case(normalized, model_path, extractor_path)
      mitre.mapper.MitreMapper(rules_dir=None).map(category, prediction, anomaly_score, feature_vector)
      reporting.browser_report_generator.BrowserReportGenerator(output_dir).generate(browser_prediction, mitre_mapping, case_id)

    All browser tools produce history/URL/password text output.
    We route the same raw_tool_output to all three normalizer inputs.
    Each browser tool focuses on a different aspect:
      - browserhistoryview / hindsight → history output
      - bft                            → BFT timeline output
      - browserpwdview                 → password view output
    """
    _emit(emit, "[Browser Pipeline] Starting browser forensics AI pipeline ...")

    browser_dir   = os.path.join(PROJECT_ROOT, "browser")
    reporting_dir = os.path.join(PROJECT_ROOT, "reporting")
    mitre_dir     = os.path.join(PROJECT_ROOT, "mitre")

    _ensure_path(browser_dir)
    _ensure_path(os.path.join(browser_dir, "normalization"))
    _ensure_path(os.path.join(browser_dir, "inference"))
    _ensure_path(os.path.join(browser_dir, "parsing"))
    _ensure_path(reporting_dir)
    _ensure_path(mitre_dir)

    # Route tool output to the correct normalizer input slot
    # Each tool produces different kinds of data; we assign accordingly.
    history_raw  = ""
    bft_raw      = ""
    passview_raw = ""

    bft_tools      = {"bft"}
    passview_tools = {"browserpwdview"}

    if tool_id in bft_tools:
        bft_raw = raw_tool_output
    elif tool_id in passview_tools:
        passview_raw = raw_tool_output
    else:
        # browserhistoryview, chromecacheview, hindsight, etc. → history slot
        history_raw = raw_tool_output

    source_file = os.path.basename(filepath)

    # ── Stage 2: Normalize ────────────────────────────────────────────────────
    _emit(emit, "[Browser][Stage 2/8] Normalizing browser artifacts ...")

    try:
        from normalization.browser_normalizer import normalize_browser_case  # type: ignore  # noqa
        normalized = normalize_browser_case(
            history_raw=history_raw,
            bft_raw=bft_raw,
            passview_raw=passview_raw,
            case_id=session_id,
            source_file=source_file,
        )
        n_urls = len(normalized.get("urls", []))
        _emit(emit, f"[Browser]   Normalized: {n_urls} unique URL(s).")
    except Exception as exc:
        return _pipeline_error("browser", "normalization", str(exc))

    # ── Stage 3-5: Predict ────────────────────────────────────────────────────
    _emit(emit, "[Browser][Stage 3/8] Running feature extraction ...")
    _emit(emit, "[Browser][Stage 4/8] Loading RF model ...")
    _emit(emit, "[Browser][Stage 5/8] Running phishing detection ...")

    model_path     = os.path.join(browser_dir, "model", "model.pkl")
    extractor_path = os.path.join(browser_dir, "feature_extraction", "feature_extractor.py")

    try:
        # FIX: bare 'from inference.predict import ...' resolves to memory/
        # due to sys.path pollution. Use importlib to load the exact file.
        _browser_pred_path = os.path.join(browser_dir, "inference", "predict.py")
        _browser_pred_mod = _load_module_from_file("browser_inference_predict", _browser_pred_path)
        predict_browser_case = _browser_pred_mod.predict_browser_case
        predict_result = predict_browser_case(normalized, model_path, extractor_path)
        summary = predict_result.get("summary", {})
        phishing_count = summary.get("phishing_count", 0)
        total_urls     = summary.get("total_urls", 0)
        phishing_rate  = summary.get("phishing_rate", 0)
        _emit(emit, f"[Browser]   URLs: {total_urls}  Phishing: {phishing_count}  Rate: {phishing_rate}%")
    except Exception as exc:
        return _pipeline_error("browser", "prediction", str(exc))

    # Derive overall prediction and anomaly_score from the per-URL results
    prediction = "MALICIOUS" if phishing_count > 0 else "SAFE"
    phishing_confidences = [
        p["confidence"] for p in predict_result.get("predictions", [])
        if p.get("prediction") == "phishing"
    ]
    anomaly_score = max(phishing_confidences) if phishing_confidences else 0.0

    # Build the case-level feature vector for MITRE (same logic as run_pipeline.py)
    feature_vector = {
        "phishing_count":        summary.get("phishing_count", 0),
        "high_risk_count":       summary.get("high_risk_count", 0),
        "login_phishing_count":  summary.get("login_phishing_count", 0),
        "phishing_rate":         summary.get("phishing_rate", 0),
        "has_download_phishing": int(any(
            p.get("prediction") == "phishing" and p.get("is_download_url")
            for p in predict_result.get("predictions", [])
        )),
        "total_urls": total_urls,
    }

    # ── Stage 6: MITRE (ai_engine/mitre/mapper.py — browser category) ─────────
    _emit(emit, "[Browser][Stage 6/8] Running MITRE ATT&CK mapping ...")

    mitre_mapping: dict = {}
    try:
        from mapper import MitreMapper as AiMitreMapper  # type: ignore  # noqa
        mapper = AiMitreMapper()
        mitre_mapping = mapper.map(
            category="browser",
            prediction=prediction,
            anomaly_score=anomaly_score,
            feature_vector=feature_vector,
        )
        risk_level = mitre_mapping.get("risk_level", "UNKNOWN")
        techniques = mitre_mapping.get("techniques", [])
        _emit(emit, f"[Browser]   MITRE: {len(techniques)} technique(s), risk={risk_level}")
    except Exception as exc:
        _emit(emit, f"[Browser][WARN] MITRE mapping failed: {exc}")
        mitre_mapping = {"techniques": [], "risk_level": "UNKNOWN", "recommendations": []}
        risk_level = "UNKNOWN"

    # ── Stage 7: Report (browser_report_generator.py) ─────────────────────────
    _emit(emit, "[Browser][Stage 7/8] Generating browser forensic report ...")

    report_paths: dict = {}
    try:
        from browser_report_generator import BrowserReportGenerator  # type: ignore  # noqa
        report_gen = BrowserReportGenerator(output_dir=output_dir)
        report_paths = report_gen.generate(
            browser_prediction=predict_result,
            mitre_mapping=mitre_mapping if mitre_mapping.get("techniques") else None,
            case_id=session_id,
        )
        _emit(emit, f"[Browser]   Report: {report_paths.get('html', 'N/A')}")
    except Exception as exc:
        _emit(emit, f"[Browser][WARN] Report generation failed: {exc}")

    _emit(emit, "[Browser][Stage 8/8] Browser pipeline complete.")
    return _build_result(
        prediction=prediction,
        risk_level=risk_level,
        anomaly_score=anomaly_score,
        confidence=anomaly_score,
        mitre_mapping=mitre_mapping,
        report_paths=report_paths,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  MALWARE PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def _run_malware_pipeline(
    *, tool_id, filepath, raw_tool_output, session_id, output_dir, emit
) -> dict:
    """
    Malware pipeline — verified against malware/run_pipeline.py:
      malware.normalization.malware_normalizer.normalize_malware_case(
          pe_file_path, pestudio_raw, die_raw, floss_raw, case_id, features_py_path)
      malware.inference.predict.predict_malware_case(normalized, model_path, scaler_path)
      mitre.mapper.MitreMapper(rules_dir=None).map(category, prediction, anomaly_score, feature_vector)
      reporting.report_generator.ForensicReportGenerator(output_dir).generate(mitre_mapping, prediction_data, feature_vector, case_id)

    Model files (VERIFIED):
      malware/models/malware_rf_model.pkl
      malware/models/malware_scaler.pkl
    """
    _emit(emit, "[Malware Pipeline] Starting malware forensics AI pipeline ...")

    malware_dir   = os.path.join(PROJECT_ROOT, "malware")
    reporting_dir = os.path.join(PROJECT_ROOT, "reporting")
    mitre_dir     = os.path.join(PROJECT_ROOT, "mitre")

    _ensure_path(malware_dir)
    _ensure_path(os.path.join(malware_dir, "normalization"))
    _ensure_path(os.path.join(malware_dir, "inference"))
    _ensure_path(os.path.join(malware_dir, "parsing"))
    _ensure_path(os.path.join(malware_dir, "feature_extraction"))
    _ensure_path(reporting_dir)
    _ensure_path(mitre_dir)

    model_path     = os.path.join(malware_dir, "models", "malware_rf_model.pkl")
    scaler_path    = os.path.join(malware_dir, "models", "malware_scaler.pkl")
    features_py    = os.path.join(malware_dir, "feature_extraction", "pe_feature_extractor.py")

    # Route tool output to the correct normalizer input slot.
    # Each malware tool produces different kind of output:
    pestudio_tools = {"pestudio", "exeinfope", "resourcehacker"}
    die_tools      = {"die"}
    floss_tools    = {"floss", "rlpack"}

    pestudio_raw = raw_tool_output if tool_id in pestudio_tools else ""
    die_raw      = raw_tool_output if tool_id in die_tools      else ""
    floss_raw    = raw_tool_output if tool_id in floss_tools     else ""

    # If none matched, route to pestudio (most informative for PE analysis)
    if not any([pestudio_raw, die_raw, floss_raw]):
        pestudio_raw = raw_tool_output

    # ── Stage 2: Normalize ────────────────────────────────────────────────────
    _emit(emit, "[Malware][Stage 2/8] Normalizing malware artifacts (PE + tool output) ...")

    try:
        from normalization.malware_normalizer import normalize_malware_case  # type: ignore  # noqa
        normalized = normalize_malware_case(
            pe_file_path=filepath,
            pestudio_raw=pestudio_raw,
            die_raw=die_raw,
            floss_raw=floss_raw,
            case_id=session_id,
            features_py_path=features_py if os.path.exists(features_py) else None,
        )
        has_ember = normalized.get("ember_features") is not None
        _emit(emit, f"[Malware]   Normalized: EMBER features={'YES' if has_ember else 'NO (PE extraction skipped)'}  "
                    f"risk_score={normalized.get('enrichment', {}).get('risk_score', 'N/A')}")
    except Exception as exc:
        return _pipeline_error("malware", "normalization", str(exc))

    # ── Stage 3-5: Predict ────────────────────────────────────────────────────
    _emit(emit, "[Malware][Stage 3/8] Running feature extraction ...")
    _emit(emit, "[Malware][Stage 4/8] Loading RF model ...")
    _emit(emit, "[Malware][Stage 5/8] Running malware classification ...")

    try:
        # FIX: bare 'from inference.predict import ...' resolves to memory/
        _malware_pred_path = os.path.join(malware_dir, "inference", "predict.py")
        _malware_pred_mod = _load_module_from_file("malware_inference_predict", _malware_pred_path)
        predict_malware_case = _malware_pred_mod.predict_malware_case
        predict_result = predict_malware_case(normalized, model_path, scaler_path)

        if "error" in predict_result:
            _emit(emit, f"[Malware][WARN] Prediction error: {predict_result['error']}")
            # Still continue — enrichment block may have useful data
            ml_prediction   = "SAFE"
            ml_confidence   = 0.0
            anomaly_score   = 0.0
        else:
            verdict       = predict_result.get("verdict", {})
            ml_result     = predict_result.get("ml_result", {})
            final_pred    = verdict.get("final_prediction") or ml_result.get("prediction", "benign")
            ml_prediction  = "MALICIOUS" if str(final_pred).lower() == "malware" else "SAFE"
            ml_confidence  = float(ml_result.get("malware_prob", 0.0))
            anomaly_score  = ml_confidence

        prediction = ml_prediction
        _emit(emit, f"[Malware]   Prediction: {prediction}  confidence: {ml_confidence:.4f}")
    except Exception as exc:
        return _pipeline_error("malware", "prediction", str(exc))

    # Build the flat feature_vector for MITRE/report (same as run_pipeline.py's build_feature_vector)
    enrichment = predict_result.get("enrichment", {})
    caps       = enrichment.get("capabilities", {})
    strings_info = enrichment.get("strings_info", {})
    feature_vector = {
        "has_injection":        int(bool(caps.get("has_injection"))),
        "has_anti_analysis":    int(bool(caps.get("has_anti_analysis"))),
        "has_network":          int(bool(caps.get("has_network"))),
        "has_persistence":      int(bool(caps.get("has_persistence"))),
        "has_c2_config":        int(bool(caps.get("has_c2_config"))),
        "has_shell_commands":   int(bool(caps.get("has_shell_commands"))),
        "has_cmd":              int(bool(caps.get("has_cmd"))),
        "has_powershell":       int(bool(caps.get("has_powershell"))),
        "has_http":             int(bool(caps.get("has_http"))),
        "has_registry":         int(bool(caps.get("has_registry"))),
        "is_packed":            int(bool(caps.get("is_packed"))),
        "injection_api_count":  len(enrichment.get("injection_apis", [])),
        "c2_string_count":      strings_info.get("c2_string_count", 0),
        "shell_command_count":  strings_info.get("shell_command_count", 0),
        "suspicious_api_count": strings_info.get("suspicious_api_count", 0),
        "risk_score":           enrichment.get("risk_score", 0),
    }

    # ── Stage 6: MITRE ────────────────────────────────────────────────────────
    _emit(emit, "[Malware][Stage 6/8] Running MITRE ATT&CK mapping ...")

    mitre_mapping: dict = {}
    try:
        from mapper import MitreMapper as AiMitreMapper  # type: ignore  # noqa
        mapper = AiMitreMapper()
        mitre_mapping = mapper.map(
            category="malware",
            prediction=prediction,
            anomaly_score=anomaly_score,
            feature_vector=feature_vector,
        )
        risk_level = mitre_mapping.get("risk_level", "UNKNOWN")
        techniques = mitre_mapping.get("techniques", [])
        _emit(emit, f"[Malware]   MITRE: {len(techniques)} technique(s), risk={risk_level}")
    except Exception as exc:
        _emit(emit, f"[Malware][WARN] MITRE mapping failed: {exc}")
        mitre_mapping = {"techniques": [], "risk_level": "UNKNOWN", "recommendations": []}
        risk_level = "UNKNOWN"

    # ── Stage 7: Report ───────────────────────────────────────────────────────
    _emit(emit, "[Malware][Stage 7/8] Generating forensic report ...")

    report_paths: dict = {}
    try:
        from report_generator import ForensicReportGenerator as AiReportGen  # type: ignore  # noqa
        report_gen = AiReportGen(output_dir=output_dir)
        report_paths = report_gen.generate(
            mitre_mapping=mitre_mapping,
            prediction_data=predict_result,
            feature_vector=feature_vector,
            case_id=session_id,
        )
        _emit(emit, f"[Malware]   Report: {report_paths.get('html', 'N/A')}")
    except Exception as exc:
        _emit(emit, f"[Malware][WARN] Report generation failed: {exc}")

    _emit(emit, "[Malware][Stage 8/8] Malware pipeline complete.")
    return _build_result(
        prediction=prediction,
        risk_level=risk_level,
        anomaly_score=anomaly_score,
        confidence=ml_confidence,
        mitre_mapping=mitre_mapping,
        report_paths=report_paths,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  NETWORK PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def _run_network_pipeline(
    *, tool_id, filepath, raw_tool_output, session_id, output_dir, emit
) -> dict:
    """
    Network pipeline — verified against network/run_pipeline.py:
      network.inference.predict.predict_network_case(raw_tshark_csv_text, case_id, source_file)
      mitre.mapper.MitreMapper(rules_dir=None).map(category, prediction, anomaly_score, feature_vector)
      reporting.report_generator.ForensicReportGenerator(output_dir).generate(mitre_mapping, prediction_data, feature_vector, case_id)

    CRITICAL: predict_network_case() expects RAW PER-PACKET TSHARK CSV — NOT the
    human-readable tshark report. The tshark_tool generates the human-readable report.
    We must run the specialized tshark CSV command to get the data the model needs.

    Required tshark CSV fields (10 columns, separator=,):
      frame.time_epoch, ip.src, ip.dst, tcp.srcport, tcp.dstport,
      frame.len, tcp.flags.syn, tcp.flags.reset, tcp.flags.push, tcp.flags.ack

    Model files (VERIFIED):
      network/models/network_isolation_forest.pkl
      network/models/network_scaler.pkl
    """
    _emit(emit, "[Network Pipeline] Starting network forensics AI pipeline ...")

    network_dir   = os.path.join(PROJECT_ROOT, "network")
    reporting_dir = os.path.join(PROJECT_ROOT, "reporting")
    mitre_dir     = os.path.join(PROJECT_ROOT, "mitre")

    _ensure_path(network_dir)
    _ensure_path(os.path.join(network_dir, "inference"))
    _ensure_path(os.path.join(network_dir, "feature_extraction"))
    _ensure_path(reporting_dir)
    _ensure_path(mitre_dir)

    source_file = os.path.basename(filepath)
    ext = os.path.splitext(filepath)[1].lower()

    # ── Stage 2: Generate tshark CSV (the specific 10-column format) ──────────
    _emit(emit, "[Network][Stage 2/8] Generating per-packet tshark CSV for ML model ...")

    raw_tshark_csv = ""

    # If the uploaded file is a PCAP, run tshark with the exact required fields
    if ext in (".pcap", ".pcapng", ".cap"):
        import shutil, subprocess
        tshark_bin = shutil.which("tshark")
        # FIX: tshark is often NOT on PATH even when Wireshark is installed on Windows
        if tshark_bin is None:
            for _cand in [
                r"C:\Program Files\Wireshark\tshark.exe",
                r"C:\Program Files (x86)\Wireshark\tshark.exe",
            ]:
                if os.path.isfile(_cand):
                    tshark_bin = _cand
                    break
        if tshark_bin:
            # FIX 1: -Y tcp filters out non-TCP packets (UDP/ICMP/ARP produce rows
            #   with empty port and flag fields which build_flows() then skips,
            #   yielding zero flows and the "No valid TCP flows" error).
            # FIX 2: tcp.flags.syn etc. are emitted as hex ("0x00000002") by many
            #   Wireshark builds, not plain 0/1.  _normalize_tshark_csv_flags()
            #   converts them before build_flows() calls int() on those fields.
            tshark_cmd = (
                f'"{tshark_bin}" -r "{filepath}" -Y tcp -T fields '
                f'-e frame.time_epoch -e ip.src -e ip.dst '
                f'-e tcp.srcport -e tcp.dstport -e frame.len '
                f'-e tcp.flags.syn -e tcp.flags.reset -e tcp.flags.push -e tcp.flags.ack '
                f'-E separator=,'
            )
            _emit(emit, f"[Network]   tshark: {tshark_bin}")
            _emit(emit, f"[Network]   Running (TCP-only): {tshark_cmd[:120]}...")
            try:
                result = subprocess.run(
                    tshark_cmd, shell=True, capture_output=True, text=True, timeout=120
                )
                if result.returncode != 0 and result.stderr.strip():
                    _emit(emit, f"[Network][WARN] tshark stderr: {result.stderr.strip()[:300]}")
                raw_tshark_csv = _normalize_tshark_csv_flags(result.stdout)
                line_count = len([l for l in raw_tshark_csv.splitlines() if l.strip()])
                _emit(emit, f"[Network]   tshark CSV (hex-normalised): {line_count} TCP packet lines.")
                if line_count > 0:
                    for _sample in [l for l in raw_tshark_csv.splitlines() if l.strip()][:2]:
                        _emit(emit, f"[Network]   sample: {_sample}")
            except Exception as exc:
                _emit(emit, f"[Network][WARN] tshark CSV generation failed: {exc}")
        else:
            _emit(emit, "[Network][WARN] tshark not found (checked PATH + C:\\Program Files\\Wireshark\\).")

    elif ext == ".csv":
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                raw_tshark_csv = _normalize_tshark_csv_flags(f.read())
            sample_lines = [l for l in raw_tshark_csv.splitlines() if l.strip()][:3]
            if sample_lines:
                col_counts = [len(l.split(",")) for l in sample_lines]
                if all(c == 10 for c in col_counts):
                    _emit(emit, f"[Network]   CSV: 10-column tshark format, {len(sample_lines)} lines.")
                else:
                    _emit(emit, f"[Network][WARN] CSV has {col_counts[0]} cols (expected 10).")
        except Exception as exc:
            _emit(emit, f"[Network][WARN] Could not read CSV: {exc}")

    elif ext == ".txt":
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = _normalize_tshark_csv_flags(f.read())
            sample_lines = [l for l in content.splitlines() if l.strip()][:3]
            if sample_lines and all(len(l.split(",")) == 10 for l in sample_lines):
                raw_tshark_csv = content
                _emit(emit, "[Network]   Detected 10-column tshark CSV in .txt file.")
            else:
                _emit(emit, "[Network][WARN] .txt file is not 10-column tshark CSV.")
        except Exception as exc:
            _emit(emit, f"[Network][WARN] Could not read .txt file: {exc}")

    if not raw_tshark_csv.strip():
        _emit(emit, "[Network][WARN] No valid tshark CSV data available — prediction will return error.")
        raw_tshark_csv = ""

    # ── Stage 3-5: Feature extraction + Prediction ────────────────────────────
    _emit(emit, "[Network][Stage 3/8] Parsing network flows (see diagnostics below) ...")
    # Run diagnostic before calling score_flows() so the live log shows
    # exactly how many packets are read, accepted, and why each is rejected.
    _debug_flow_parsing(raw_tshark_csv, emit)
    _emit(emit, "[Network][Stage 4/8] Loading Isolation Forest model ...")
    _emit(emit, "[Network][Stage 5/8] Scoring flows ...")

    try:
        # FIX: bare 'from inference.predict import ...' resolves to memory/
        _network_pred_path = os.path.join(network_dir, "inference", "predict.py")
        _network_pred_mod = _load_module_from_file("network_inference_predict", _network_pred_path)
        predict_network_case = _network_pred_mod.predict_network_case
        predict_result = predict_network_case(
            raw_tshark_csv_text=raw_tshark_csv,
            case_id=session_id,
            source_file=source_file,
        )

        if "error" in predict_result:
            _emit(emit, f"[Network][WARN] Prediction error: {predict_result['error']}")
            prediction    = "SAFE"
            anomaly_score = 0.0
            feature_vector = {}
        else:
            ml_result     = predict_result.get("ml_result", {})
            prediction    = ml_result.get("prediction", "SAFE")
            anomaly_score = float(ml_result.get("anomaly_score", 0.0))
            feature_vector = predict_result.get("worst_flow", {}).get("feature_vector", {})
            total_flows   = ml_result.get("total_flows_analyzed", 0)
            bad_flows     = ml_result.get("malicious_flow_count", 0)
            _emit(emit, f"[Network]   Prediction: {prediction}  score: {anomaly_score:.4f}  "
                        f"flows: {total_flows}  malicious: {bad_flows}")
    except Exception as exc:
        return _pipeline_error("network", "prediction", str(exc))

    # ── Stage 6: MITRE ────────────────────────────────────────────────────────
    _emit(emit, "[Network][Stage 6/8] Running MITRE ATT&CK mapping ...")

    mitre_mapping: dict = {}
    try:
        from mapper import MitreMapper as AiMitreMapper  # type: ignore  # noqa
        mapper = AiMitreMapper()
        mitre_mapping = mapper.map(
            category="network",
            prediction=prediction,
            anomaly_score=anomaly_score,
            feature_vector=feature_vector,
        )
        risk_level = mitre_mapping.get("risk_level", "UNKNOWN")
        techniques = mitre_mapping.get("techniques", [])
        _emit(emit, f"[Network]   MITRE: {len(techniques)} technique(s), risk={risk_level}")
    except Exception as exc:
        _emit(emit, f"[Network][WARN] MITRE mapping failed: {exc}")
        mitre_mapping = {"techniques": [], "risk_level": "UNKNOWN", "recommendations": []}
        risk_level = "UNKNOWN"

    # ── Stage 7: Report ───────────────────────────────────────────────────────
    _emit(emit, "[Network][Stage 7/8] Generating forensic report ...")

    report_paths: dict = {}
    try:
        from report_generator import ForensicReportGenerator as AiReportGen  # type: ignore  # noqa
        report_gen = AiReportGen(output_dir=output_dir)
        report_paths = report_gen.generate(
            mitre_mapping=mitre_mapping,
            prediction_data=predict_result,
            feature_vector=feature_vector,
            case_id=session_id,
        )
        _emit(emit, f"[Network]   Report: {report_paths.get('html', 'N/A')}")
    except Exception as exc:
        _emit(emit, f"[Network][WARN] Report generation failed: {exc}")

    _emit(emit, "[Network][Stage 8/8] Network pipeline complete.")
    return _build_result(
        prediction=prediction,
        risk_level=risk_level,
        anomaly_score=anomaly_score,
        confidence=None,
        mitre_mapping=mitre_mapping,
        report_paths=report_paths,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  Shared helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _core_mitre(
    category: str,
    prediction_data: dict,
    feature_vector: dict,
    emit: Callable | None,
) -> tuple[dict, str]:
    """Run core/mitre/mapper.py — used by memory, database, disk."""
    _ensure_path(os.path.join(PROJECT_ROOT, "core", "mitre"))
    try:
        from core.mitre.mapper import MitreMapper as CoreMitreMapper  # type: ignore  # noqa
        mapper = CoreMitreMapper(project_root=PROJECT_ROOT)
        mitre_mapping = mapper.map(
            category=category,
            prediction_data=prediction_data,
            feature_vector=feature_vector,
        )
        risk_level = mitre_mapping.get("risk_level", "UNKNOWN")
        techniques = mitre_mapping.get("techniques", [])
        _emit(emit, f"[{category.title()}]   MITRE: {len(techniques)} technique(s), risk={risk_level}")
        return mitre_mapping, risk_level
    except Exception as exc:
        _emit(emit, f"[{category.title()}][WARN] MITRE mapping failed: {exc}")
        return {"techniques": [], "risk_level": "UNKNOWN", "recommendations": []}, "UNKNOWN"


def _core_report(
    *,
    mitre_mapping: dict,
    prediction_data: dict,
    feature_vector: dict,
    output_dir: str,
    case_id: str,
    emit: Callable | None,
) -> dict:
    """Run core/reporting/report_generator.py — used by memory, database, disk."""
    _ensure_path(os.path.join(PROJECT_ROOT, "core", "reporting"))
    try:
        from core.reporting.report_generator import ForensicReportGenerator as CoreReportGen  # type: ignore  # noqa
        report_gen = CoreReportGen(output_dir=output_dir)
        report_paths = report_gen.generate(
            mitre_mapping=mitre_mapping,
            prediction_data=prediction_data,
            feature_vector=feature_vector,
            case_id=case_id,
        )
        _emit(emit, f"   Report: {report_paths.get('html', 'N/A')}")
        return report_paths
    except Exception as exc:
        _emit(emit, f"   [WARN] Report generation failed: {exc}")
        return {}


def _normalize_tshark_csv_flags(raw_csv: str) -> str:
    """
    Normalise tshark TCP flag fields from hex to 0/1 integers.

    Problem
    -------
    tshark outputs ``tcp.flags.syn``, ``tcp.flags.reset``, etc. as
    HEX strings on many Wireshark builds::

        1751234567.1,10.0.0.1,8.8.8.8,54321,443,1420,0x00000002,0x00000000,0x00000008,0x00000010

    ``build_flows()`` does ``int(parts[6])`` which raises ``ValueError`` on
    ``"0x00000002"`` — the exception is silently caught and the packet is
    skipped.  When ALL packets are skipped, ``build_flows()`` returns an empty
    dict and ``predict_network_case()`` returns the
    ``"No valid TCP flows could be parsed"`` error.

    Fix
    ---
    Convert any ``0x...`` hex flag field to ``0`` (if zero) or ``1`` (if
    non-zero) BEFORE the CSV is passed to ``build_flows()``.
    We only touch columns 6–9 (the four flag columns) and leave all others
    (including the timestamp float and the two IPs) untouched.
    """
    import re as _re
    _hex_re = _re.compile(r'0x[0-9a-fA-F]+')

    def _normalise_line(line: str) -> str:
        parts = line.split(",")
        if len(parts) != 10:
            return line  # wrong column count — let build_flows() reject it
        # Columns 6–9 are the four flag fields
        for i in range(6, 10):
            field = parts[i].strip()
            if _hex_re.fullmatch(field):
                # Non-zero hex → 1, zero hex → 0
                parts[i] = "1" if int(field, 16) != 0 else "0"
        return ",".join(parts)

    lines = []
    for line in raw_csv.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lines.append(_normalise_line(stripped))
    return "\n".join(lines)


def _debug_flow_parsing(raw_csv: str, emit: Callable | None) -> None:
    """
    Diagnostic mirror of build_flows() — walks the CSV line-by-line through
    every gate that build_flows() applies, logging a tally and the first few
    examples of each rejection reason.

    This function DOES NOT call or replace build_flows(); it only produces
    diagnostic emit() messages so the user can see exactly why packets are
    dropped before score_flows() is called.

    Gates (same order as build_flows() in tshark_flow_fields.py):
      1. Empty line
      2. Column count != 10
      3. ValueError on type conversion (float time, int ports/flags)
      4. Empty src_ip / dst_ip / src_port / dst_port
      [accepted]
    """
    n_total       = 0
    n_empty       = 0
    n_wrong_cols  = 0
    n_parse_error = 0
    n_no_addr     = 0
    n_accepted    = 0

    # Keep up to 3 rejected-line samples per bucket for the log
    _MAX_EXAMPLES = 3
    examples_wrong_cols:  list[str] = []
    examples_parse_error: list[str] = []
    examples_no_addr:     list[str] = []

    for raw_line in raw_csv.splitlines():
        n_total += 1
        line = raw_line.strip()

        # Gate 1 — empty line
        if not line:
            n_empty += 1
            continue

        # Gate 2 — column count
        parts = line.split(",")
        if len(parts) != 10:
            n_wrong_cols += 1
            if len(examples_wrong_cols) < _MAX_EXAMPLES:
                examples_wrong_cols.append(f"{len(parts)} cols: {line[:120]}")
            continue

        # Gate 3 — type conversion (mirrors build_flows() try/except ValueError)
        try:
            _t   = float(parts[0])
            _si  = parts[1]
            _di  = parts[2]
            _sp  = parts[3]
            _dp  = parts[4]
            _len = int(parts[5]) if parts[5] else 0
            _syn = int(parts[6]) if parts[6] else 0
            _rst = int(parts[7]) if parts[7] else 0
            _psh = int(parts[8]) if parts[8] else 0
            _ack = int(parts[9]) if parts[9] else 0
        except ValueError as e:
            n_parse_error += 1
            if len(examples_parse_error) < _MAX_EXAMPLES:
                examples_parse_error.append(f"ValueError({e}): {line[:120]}")
            continue

        # Gate 4 — missing addresses/ports
        if not _si or not _di or not _sp or not _dp:
            n_no_addr += 1
            if len(examples_no_addr) < _MAX_EXAMPLES:
                examples_no_addr.append(f"empty field(s) [ip.src={_si!r} ip.dst={_di!r} sport={_sp!r} dport={_dp!r}]: {line[:80]}")
            continue

        n_accepted += 1

    # --- Emit summary ----------------------------------------------------------
    _emit(emit, "[Network][DEBUG] --- CSV -> Flow parsing diagnostics ---")
    _emit(emit, f"[Network][DEBUG]   Total lines in CSV      : {n_total}")
    _emit(emit, f"[Network][DEBUG]   Empty / blank lines     : {n_empty}")
    _emit(emit, f"[Network][DEBUG]   Wrong column count      : {n_wrong_cols}  (expected 10)")
    _emit(emit, f"[Network][DEBUG]   Type conversion errors  : {n_parse_error}  (ValueError on int/float)")
    _emit(emit, f"[Network][DEBUG]   Missing IP or port      : {n_no_addr}")
    _emit(emit, f"[Network][DEBUG]   OK Accepted packets      : {n_accepted}")

    if examples_wrong_cols:
        _emit(emit, f"[Network][DEBUG]   Wrong-cols examples ({len(examples_wrong_cols)}):")
        for ex in examples_wrong_cols:
            _emit(emit, f"[Network][DEBUG]     {ex}")

    if examples_parse_error:
        _emit(emit, f"[Network][DEBUG]   Parse-error examples ({len(examples_parse_error)}):")
        for ex in examples_parse_error:
            _emit(emit, f"[Network][DEBUG]     {ex}")

    if examples_no_addr:
        _emit(emit, f"[Network][DEBUG]   Missing-addr examples ({len(examples_no_addr)}):")
        for ex in examples_no_addr:
            _emit(emit, f"[Network][DEBUG]     {ex}")

    if n_accepted == 0:
        _emit(emit, "[Network][DEBUG] WARN: Zero packets accepted -- build_flows() will return 0 flows -> 'No valid TCP flows' error.")
    else:
        # Estimate flows: accepted packets grouped by bidirectional 4-tuple
        seen_keys: set = set()
        for raw_line in raw_csv.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) != 10:
                continue
            try:
                si, di, sp, dp = parts[1], parts[2], parts[3], parts[4]
                float(parts[0])
                int(parts[5] or "0")
                int(parts[6] or "0")
            except ValueError:
                continue
            if not si or not di or not sp or not dp:
                continue
            key = tuple(sorted([(si, sp), (di, dp)]))
            seen_keys.add(key)
        _emit(emit, f"[Network][DEBUG]   Estimated unique flows  : {len(seen_keys)}")
    _emit(emit, "[Network][DEBUG] --- end diagnostics ---")


def _build_result(
    *,
    prediction: str,
    risk_level: str,
    anomaly_score: float,
    confidence: float | None,
    mitre_mapping: dict,
    report_paths: dict,
) -> dict:
    """Build the unified result dict returned to app.py."""
    techniques = mitre_mapping.get("techniques", [])
    recommendations = mitre_mapping.get("recommendations", [])

    return {
        "stage":               "complete",
        "prediction":          prediction,
        "risk_level":          risk_level,
        "anomaly_score":       round(anomaly_score, 4),
        "confidence":          round(confidence, 4) if confidence is not None else None,
        "mitre_techniques":    techniques,
        "recommendations":     recommendations,
        "report_html_location": report_paths.get("html"),
        "report_json_location": report_paths.get("json"),
        "report_md_location":   report_paths.get("md"),
    }


def _pipeline_error(category: str, stage: str, reason: str) -> dict:
    """Return a standardised error result."""
    logger.error("[%s] Pipeline error at stage=%s: %s", category, stage, reason)
    return {
        "stage": "error",
        "error": {"category": category, "stage": stage, "reason": reason},
    }
