"""
run_pipeline.py — Network End-to-End Pipeline Runner
─────────────────────────────────────────────────────
Chains: raw tshark per-packet CSV -> predict_network_case() (Isolation Forest)
        -> ai_engine/mitre/mapper.py -> ai_engine/reporting/report_generator.py

This is permanent pipeline glue, not a test.

Get the raw per-packet CSV first:
    tshark -r <pcap> -T fields \\
        -e frame.time_epoch -e ip.src -e ip.dst \\
        -e tcp.srcport -e tcp.dstport -e frame.len \\
        -e tcp.flags.syn -e tcp.flags.reset -e tcp.flags.push -e tcp.flags.ack \\
        -E separator=, > flow_fields.csv

Usage:
    python run_pipeline.py --csv "flow_fields.csv" --case-id "case_001" --source-file "malicious_traffic.pcap"

Output: ai_engine/network/output/<case_id>/
    predict_result.json
    mitre_mapping.json
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
sys.path.insert(0, os.path.join(AI_ENGINE_DIR, "mitre"))
sys.path.insert(0, os.path.join(AI_ENGINE_DIR, "reporting"))

from inference.predict import predict_network_case  # noqa: E402
from mapper import MitreMapper  # noqa: E402
from report_generator import ForensicReportGenerator  # noqa: E402

OUTPUT_ROOT = os.path.join(BASE, "output")


def run(csv_path: str, case_id: str, source_file: str) -> dict:
    out_dir = os.path.join(OUTPUT_ROOT, case_id)
    os.makedirs(out_dir, exist_ok=True)

    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        raw_csv = f.read()

    # 1) Predict (ML scoring per flow, rolled up to case-level verdict)
    print("[1/3] Scoring flows with Isolation Forest...")
    predict_result = predict_network_case(raw_csv, case_id=case_id, source_file=source_file)
    with open(os.path.join(out_dir, "predict_result.json"), "w", encoding="utf-8") as f:
        json.dump(predict_result, f, indent=2, default=str, ensure_ascii=False)

    if "error" in predict_result:
        print(f"[!] {predict_result['error']}")
        return {"case_id": case_id, "error": predict_result["error"], "output_dir": out_dir}

    # 2) MITRE mapping (uses the worst (most anomalous) flow's feature vector)
    print("[2/3] Mapping to MITRE ATT&CK...")
    ml_result = predict_result.get("ml_result", {})
    prediction = ml_result.get("prediction", "SAFE")
    anomaly_score = ml_result.get("anomaly_score", 0.0)
    feature_vector = predict_result.get("worst_flow", {}).get("feature_vector", {})

    mapper = MitreMapper()
    mitre_mapping = mapper.map(
        category="network", prediction=prediction,
        anomaly_score=anomaly_score, feature_vector=feature_vector,
    )
    MitreMapper.save_json(mitre_mapping, os.path.join(out_dir, "mitre_mapping.json"))

    # 3) Report
    print("[3/3] Generating reports (json/md/html)...")
    report_gen = ForensicReportGenerator(output_dir=out_dir)
    report_paths = report_gen.generate(
        mitre_mapping=mitre_mapping, prediction_data=predict_result,
        feature_vector=feature_vector, case_id=case_id,
    )

    print("\n" + "=" * 60)
    print(f"Pipeline complete for case: {case_id}")
    print("=" * 60)
    print(f"  Verdict          : {prediction} ({mitre_mapping['risk_level']})")
    print(f"  Flows analyzed   : {ml_result.get('total_flows_analyzed', 0)}")
    print(f"  Malicious flows  : {ml_result.get('malicious_flow_count', 0)}")
    print(f"  Techniques       : {mitre_mapping['techniques_matched']} matched")
    print(f"  Output dir       : {out_dir}")
    for fmt, path in report_paths.items():
        print(f"    [{fmt.upper():>4}] {path}")

    return {
        "case_id": case_id, "prediction": prediction,
        "risk_level": mitre_mapping["risk_level"], "output_dir": out_dir,
    }


def main():
    ap = argparse.ArgumentParser(description="Network end-to-end pipeline runner")
    ap.add_argument("--csv", required=True, help="Path to raw per-packet tshark CSV")
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--source-file", default="unknown.pcap")
    args = ap.parse_args()
    run(args.csv, args.case_id, args.source_file)


if __name__ == "__main__":
    main()
