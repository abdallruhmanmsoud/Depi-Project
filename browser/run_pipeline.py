"""
run_pipeline.py — Browser End-to-End Pipeline Runner
─────────────────────────────────────────────────────
Chains: raw tool outputs (history/BFT/PassView) -> normalize_browser_case()
        -> predict_browser_case() -> ai_engine/mitre/mapper.py (browser_rules.json)
        -> ai_engine/reporting/browser_report_generator.py

The MITRE feature vector here is a case-level AGGREGATE (phishing_count,
high_risk_count, login_phishing_count, phishing_rate, has_download_phishing,
total_urls) built from the per-URL predict_browser_case() output — not a
per-URL vector, since browser_rules.json conditions operate at the case level.

This is permanent pipeline glue, not a test.

Usage:
    python run_pipeline.py \\
        --history "PATH_TO_history_output.txt" \\
        --bft "PATH_TO_bft_output.txt" \\
        --passview "PATH_TO_passview_output.txt" \\
        --case-id "case_001" \\
        --source-file "malicious_browser.db"

Output: ai_engine/browser/output/<case_id>/
    normalized.json
    predict_result.json
    case_report.json / .md / .html
"""
from __future__ import annotations
import argparse
import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

AI_ENGINE_DIR = os.path.abspath(os.path.join(BASE, ".."))
sys.path.insert(0, os.path.join(AI_ENGINE_DIR, "reporting"))
sys.path.insert(0, os.path.join(AI_ENGINE_DIR, "mitre"))

from normalization.browser_normalizer import normalize_browser_case  # noqa: E402
from inference.predict import predict_browser_case  # noqa: E402
from browser_report_generator import BrowserReportGenerator  # noqa: E402
from mapper import MitreMapper  # noqa: E402

MODEL_PATH     = os.path.join(BASE, "model", "model.pkl")
EXTRACTOR_PATH = os.path.join(BASE, "feature_extraction", "feature_extractor.py")
OUTPUT_ROOT    = os.path.join(BASE, "output")


def build_feature_vector(predict_result: dict) -> dict:
    """Aggregate the per-URL predict_browser_case() output into the flat
    case-level dict browser_rules.json conditions expect."""
    summary = predict_result.get("summary", {})
    predictions = predict_result.get("predictions", [])
    has_download_phishing = int(any(
        p.get("prediction") == "phishing" and p.get("is_download_url")
        for p in predictions
    ))
    return {
        "phishing_count":        summary.get("phishing_count", 0),
        "high_risk_count":       summary.get("high_risk_count", 0),
        "login_phishing_count":  summary.get("login_phishing_count", 0),
        "phishing_rate":         summary.get("phishing_rate", 0),
        "has_download_phishing": has_download_phishing,
        "total_urls":            summary.get("total_urls", 0),
    }


def run(history_path: str, bft_path: str, passview_path: str, case_id: str, source_file: str) -> dict:
    out_dir = os.path.join(OUTPUT_ROOT, case_id)
    os.makedirs(out_dir, exist_ok=True)

    with open(history_path, "r", encoding="utf-8", errors="ignore") as f:
        history_raw = f.read()
    with open(bft_path, "r", encoding="utf-8", errors="ignore") as f:
        bft_raw = f.read()
    with open(passview_path, "r", encoding="utf-8", errors="ignore") as f:
        passview_raw = f.read()

    # 1) Normalize
    print("[1/3] Normalizing case (merging history/BFT/PassView, deduping URLs)...")
    normalized = normalize_browser_case(
        history_raw=history_raw, bft_raw=bft_raw, passview_raw=passview_raw,
        case_id=case_id, source_file=source_file,
    )
    with open(os.path.join(out_dir, "normalized.json"), "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2, default=str, ensure_ascii=False)

    # 2) Predict (per-URL: rule pre_check + RandomForest phishing model)
    print("[2/4] Running phishing detection (rule layer + RandomForest)...")
    predict_result = predict_browser_case(normalized, MODEL_PATH, EXTRACTOR_PATH)
    with open(os.path.join(out_dir, "predict_result.json"), "w", encoding="utf-8") as f:
        json.dump(predict_result, f, indent=2, default=str, ensure_ascii=False)

    # 3) MITRE mapping (case-level aggregate feature vector)
    print("[3/4] Mapping to MITRE ATT&CK...")
    feature_vector = build_feature_vector(predict_result)
    summary = predict_result.get("summary", {})
    prediction = "MALICIOUS" if summary.get("phishing_count", 0) > 0 else "SAFE"
    phishing_confidences = [
        p["confidence"] for p in predict_result.get("predictions", [])
        if p.get("prediction") == "phishing"
    ]
    anomaly_score = max(phishing_confidences) if phishing_confidences else 0.0

    mapper = MitreMapper()
    mitre_mapping = mapper.map(
        category="browser", prediction=prediction,
        anomaly_score=anomaly_score, feature_vector=feature_vector,
    )
    MitreMapper.save_json(mitre_mapping, os.path.join(out_dir, "mitre_mapping.json"))

    # 4) Report
    print("[4/4] Generating reports (json/md/html)...")
    report_gen = BrowserReportGenerator(output_dir=out_dir)
    report_paths = report_gen.generate(
        browser_prediction=predict_result, mitre_mapping=mitre_mapping, case_id=case_id,
    )

    print("\n" + "=" * 60)
    print(f"Pipeline complete for case: {case_id}")
    print("=" * 60)
    print(f"  Total URLs        : {summary.get('total_urls', 0)}")
    print(f"  Phishing found    : {summary.get('phishing_count', 0)} ({summary.get('phishing_rate', 0)}%)")
    print(f"  High risk URLs    : {summary.get('high_risk_count', 0)}")
    print(f"  Login+phishing    : {summary.get('login_phishing_count', 0)}")
    print(f"  Output dir        : {out_dir}")
    for fmt, path in report_paths.items():
        print(f"    [{fmt.upper():>4}] {path}")

    return {"case_id": case_id, "summary": summary, "output_dir": out_dir}


def main():
    ap = argparse.ArgumentParser(description="Browser end-to-end pipeline runner")
    ap.add_argument("--history", required=True, help="Path to BrowserHistoryView/Hindsight output")
    ap.add_argument("--bft", required=True, help="Path to BFT output")
    ap.add_argument("--passview", required=True, help="Path to WebBrowserPassView output")
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--source-file", default="unknown.db")
    args = ap.parse_args()
    run(args.history, args.bft, args.passview, args.case_id, args.source_file)


if __name__ == "__main__":
    main()
