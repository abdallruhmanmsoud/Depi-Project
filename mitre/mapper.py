"""
mapper.py — MITRE ATT&CK Mapping Engine (Mohamed's categories: malware, network, browser)
────────────────────────────────────────────────────────────────────────────
Self-contained copy of the mapping pattern, scoped to ai_engine/ only.
Independent from my_friend/core/mitre — no shared-file dependency.

Usage
-----
::
    python ai_engine/mitre/mapper.py --category malware \\
        --prediction ai_engine/malware/test_outputs/real_test_001_result.json

Output
------
Writes ``mitre_mapping.json`` to the specified ``--output`` directory
(default: ``ai_engine/mitre/``).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from rule_engine import RuleEngine, RuleMatch  # noqa: E402

logger = logging.getLogger(__name__)
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s — %(message)s"))
if not logger.handlers:
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)

# ── Tactic → recommendation mapping (generic incident-response actions) ─────
TACTIC_RECOMMENDATIONS: Dict[str, Dict[str, List[str]]] = {
    "Persistence": {
        "containment": ["Disable identified persistence mechanisms", "Remove suspicious startup entries and scheduled tasks"],
        "evidence_preservation": ["Export registry hives for offline analysis", "Snapshot current startup configuration"],
        "further_investigation": ["Inspect registry run keys and startup folders", "Check for backdoor implants in service binaries"],
    },
    "Execution": {
        "containment": ["Quarantine identified malicious executables", "Block execution of suspicious scripts"],
        "evidence_preservation": ["Acquire copies of malicious files before quarantine", "Preserve command-line audit logs"],
        "further_investigation": ["Submit executables to sandbox for dynamic analysis", "Correlate execution times with other lateral movement"],
    },
    "Defense Evasion": {
        "containment": ["Re-enable tampered security controls", "Restore modified audit configurations"],
        "evidence_preservation": ["Preserve unaltered copies of tampered logs", "Capture hidden artifacts before remediation"],
        "further_investigation": ["Analyze timestomped files for true creation dates", "Check for process hollowing or DLL side-loading"],
    },
    "Privilege Escalation": {
        "containment": ["Revoke escalated privileges immediately", "Disable compromised high-privilege accounts"],
        "evidence_preservation": ["Preserve privilege assignment audit logs", "Capture token and privilege state of suspect processes"],
        "further_investigation": ["Analyze exploit vectors used for escalation", "Check for kernel-mode rootkit indicators"],
    },
    "Command and Control": {
        "containment": ["Block suspicious IPs and domains at perimeter", "Sinkhole identified C2 domains"],
        "evidence_preservation": ["Capture full PCAP of C2 traffic before blocking", "Preserve DNS query logs"],
        "further_investigation": ["Decode C2 protocol for command extraction", "Identify all hosts communicating with C2 infrastructure"],
    },
    "Exfiltration": {
        "containment": ["Block outbound connections to identified destinations", "Enable DLP controls on affected endpoints"],
        "evidence_preservation": ["Preserve data transfer and upload logs", "Capture network flow data showing exfil volume"],
        "further_investigation": ["Determine scope and sensitivity of exfiltrated data", "Check for staged data in temporary directories"],
    },
    "Impact": {
        "containment": ["Disconnect affected systems from production network", "Halt identified destructive processes"],
        "evidence_preservation": ["Acquire forensic images of affected drives", "Preserve any ransom notes or attacker communications"],
        "further_investigation": ["Determine if data exfiltration preceded destruction", "Analyze malware for decryption possibilities"],
    },
    "Discovery": {
        "containment": ["Block source host from scanning further internal ranges", "Restrict overly broad network ACLs"],
        "evidence_preservation": ["Preserve firewall/IDS scan-alert logs", "Capture the scanning host's process list"],
        "further_investigation": ["Enumerate everything the scan touched", "Check for follow-on exploitation attempts against discovered services"],
    },
}

UNIVERSAL_ACTIONS: Dict[str, List[str]] = {
    "containment": ["Isolate host from network", "Disable compromised accounts"],
    "evidence_preservation": ["Acquire forensic images of affected media", "Preserve volatile evidence (memory, network state)"],
    "further_investigation": ["Correlate findings with SIEM logs", "Check for additional indicators of compromise (IOCs)"],
}


class MitreMapper:
    """Orchestrates MITRE ATT&CK mapping for Mohamed's malware/network/browser AI predictions."""

    def __init__(self, rules_dir: str = None) -> None:
        self.engine = RuleEngine(rules_dir=rules_dir)

    def map(self, category: str, prediction: str, anomaly_score: float, feature_vector: dict) -> dict:
        """
        Run the full MITRE mapping pipeline.

        Parameters
        ----------
        category : str
            "malware", "network", or "browser".
        prediction : str
            "MALICIOUS" or "SAFE".
        anomaly_score : float
            0.0-1.0, higher = more anomalous/malicious.
        feature_vector : dict
            Flat {feature_name: value} dict matching the category's rules JSON.
        """
        prediction = "MALICIOUS" if str(prediction).upper() == "MALICIOUS" else "SAFE"
        anomaly_score = float(anomaly_score or 0.0)

        matches: List[RuleMatch] = self.engine.evaluate(
            category=category, feature_vector=feature_vector or {},
            prediction={"anomaly_score": anomaly_score},
        )

        risk_level = self._determine_risk_level(prediction, anomaly_score, matches)
        recommendations = self._generate_recommendations(matches)
        total_rules = len(self.engine.load_rules(category))

        return self._build_output(category, prediction, anomaly_score, matches, risk_level, recommendations, total_rules)

    def _determine_risk_level(self, prediction: str, anomaly_score: float, techniques: List[RuleMatch]) -> str:
        is_malicious = prediction == "MALICIOUS"
        has_critical = any(m.severity == "Critical" for m in techniques)

        if is_malicious and (anomaly_score > 0.6 or has_critical):
            return "CRITICAL"
        if is_malicious and anomaly_score > 0.4:
            return "HIGH"
        if is_malicious or anomaly_score > 0.3:
            return "MEDIUM"
        if anomaly_score > 0.2 or len(techniques) > 0:
            return "LOW"
        return "SAFE"

    def _generate_recommendations(self, techniques: List[RuleMatch]) -> List[dict]:
        if not techniques:
            return []
        severity_priority = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
        recommendations: List[dict] = []

        for match in techniques:
            rule = match.rule
            tactic = rule.mitre_tactic
            priority = severity_priority.get(match.severity, 4)
            tactic_actions = TACTIC_RECOMMENDATIONS.get(tactic, {})

            actions: Dict[str, List[str]] = {
                "containment": list(tactic_actions.get("containment", UNIVERSAL_ACTIONS["containment"])),
                "evidence_preservation": list(tactic_actions.get("evidence_preservation", UNIVERSAL_ACTIONS["evidence_preservation"])),
                "further_investigation": list(tactic_actions.get("further_investigation", UNIVERSAL_ACTIONS["further_investigation"])),
            }
            for key, universal in UNIVERSAL_ACTIONS.items():
                existing = set(actions.get(key, []))
                for action in universal:
                    if action not in existing:
                        actions[key].append(action)

            recommendations.append({
                "priority": priority,
                "technique_id": rule.mitre_technique_id,
                "technique_name": rule.mitre_technique_name,
                "tactic": tactic,
                "actions": actions,
            })

        recommendations.sort(key=lambda r: r["priority"])
        for idx, rec in enumerate(recommendations, start=1):
            rec["priority"] = idx
        return recommendations

    def _build_output(self, category, prediction, anomaly_score, matches, risk_level, recommendations, total_rules_evaluated) -> dict:
        now = datetime.now(timezone.utc)
        timestamp_str = now.strftime("%Y%m%d_%H%M%S")

        interpretations = {
            "CRITICAL": "CRITICAL — Highly Anomalous",
            "HIGH": "HIGH — Significant Anomaly Detected",
            "MEDIUM": "MEDIUM — Moderate Anomaly Detected",
            "LOW": "LOW — Minor Anomaly Detected",
            "SAFE": "NORMAL — Safe Activity",
        }
        interpretation = interpretations.get(risk_level, f"{risk_level} — Unknown")

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        tactics_involved: List[str] = []
        techniques_list: List[dict] = []

        for match in matches:
            rule = match.rule
            severity_counts[match.severity] = severity_counts.get(match.severity, 0) + 1
            if rule.mitre_tactic not in tactics_involved:
                tactics_involved.append(rule.mitre_tactic)
            techniques_list.append({
                "rule_id": rule.rule_id,
                "id": rule.mitre_technique_id,
                "name": rule.mitre_technique_name,
                "tactic": rule.mitre_tactic,
                "confidence": match.confidence,
                "severity": match.severity,
                "description": rule.description,
                "matched_conditions": match.matched_conditions,
                "recommendation": rule.recommendation,
            })

        return {
            "case_id": f"CASE-{timestamp_str}",
            "category": category,
            "analysis_timestamp": now.isoformat(),
            "prediction": prediction,
            "anomaly_score": anomaly_score,
            "risk_level": risk_level,
            "interpretation": interpretation,
            "techniques_matched": len(matches),
            "techniques": techniques_list,
            "recommendations": recommendations,
            "summary": {
                "total_rules_evaluated": total_rules_evaluated,
                "total_rules_matched": len(matches),
                "critical_count": severity_counts.get("Critical", 0),
                "high_count": severity_counts.get("High", 0),
                "medium_count": severity_counts.get("Medium", 0),
                "low_count": severity_counts.get("Low", 0),
                "tactics_involved": tactics_involved,
            },
        }

    @staticmethod
    def load_json(path: str) -> dict:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load JSON from %s: %s", path, exc)
            return {}

    @staticmethod
    def save_json(data: dict, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
        logger.info("Saved mapping to %s", path)


def main() -> None:
    parser = argparse.ArgumentParser(description="MITRE ATT&CK Mapping Engine (Mohamed's categories).")
    parser.add_argument("--category", required=True, choices=["malware", "network", "browser"])
    parser.add_argument("--prediction", required=True, help="MALICIOUS or SAFE")
    parser.add_argument("--anomaly-score", type=float, default=0.0)
    parser.add_argument("--features", required=True, help="Path to a flat feature_vector JSON")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    feature_vector = MitreMapper.load_json(args.features)
    mapper = MitreMapper()
    result = mapper.map(args.category, args.prediction, args.anomaly_score, feature_vector)

    output_dir = args.output or _THIS_DIR
    output_path = os.path.join(output_dir, f"{args.category}_mitre_mapping.json")
    MitreMapper.save_json(result, output_path)

    print("=" * 60)
    print("MITRE ATT&CK Mapping Complete")
    print("=" * 60)
    print(f"  Category        : {result['category']}")
    print(f"  Prediction      : {result['prediction']}")
    print(f"  Risk Level      : {result['risk_level']}")
    print(f"  Rules Matched   : {result['summary'].get('total_rules_matched', 0)}")
    print(f"  Output          : {output_path}")


if __name__ == "__main__":
    main()
