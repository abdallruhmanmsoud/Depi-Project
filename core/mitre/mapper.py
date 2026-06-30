"""
mapper.py — MITRE ATT&CK Mapping Engine

Consumes prediction outputs from Memory, Database, and Disk AI pipelines
and maps findings to MITRE ATT&CK techniques using the deterministic
rule engine.

Usage
-----
::

    python core/mitre/mapper.py --category disk \\
        --prediction disk/prediction/disk_prediction.json

    python core/mitre/mapper.py --category database \\
        --prediction database/prediction/database_prediction.json

    python core/mitre/mapper.py --category memory \\
        --prediction memory/inference/predict.py \\
        --features memory/features/memory_feature_vector.json

Output
------
Writes ``mitre_mapping.json`` to the specified ``--output`` directory
(default: ``core/mitre/``).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── Resolve imports from same package ────────────────────────────────────────
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT_CANDIDATE = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))

if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

try:
    from rule_engine import RuleEngine, RuleMatch
except ImportError:
    # If running as part of a package
    from core.mitre.rule_engine import RuleEngine, RuleMatch

# ── Logging ──────────────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)
_handler = logging.StreamHandler(sys.stderr)
_handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s — %(message)s"))
if not logger.handlers:
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)

# ── Tactic → recommendation mapping ─────────────────────────────────────────
TACTIC_RECOMMENDATIONS: Dict[str, Dict[str, List[str]]] = {
    "Persistence": {
        "containment": [
            "Disable identified persistence mechanisms",
            "Remove suspicious startup entries and scheduled tasks",
        ],
        "evidence_preservation": [
            "Export registry hives for offline analysis",
            "Snapshot current startup configuration",
        ],
        "collection_steps": [
            "Collect autoruns output from affected host",
            "Enumerate scheduled tasks and services",
        ],
        "further_investigation": [
            "Inspect registry run keys and startup folders",
            "Check for backdoor implants in service binaries",
        ],
    },
    "Credential Access": {
        "containment": [
            "Reset all credentials for affected accounts",
            "Enforce multi-factor authentication immediately",
        ],
        "evidence_preservation": [
            "Preserve authentication logs before rotation",
            "Capture LSASS memory for credential extraction analysis",
        ],
        "collection_steps": [
            "Audit access logs for compromised accounts",
            "Collect security event logs from domain controller",
        ],
        "further_investigation": [
            "Analyze credential dumps for scope of compromise",
            "Check for pass-the-hash or pass-the-ticket activity",
        ],
    },
    "Execution": {
        "containment": [
            "Quarantine identified malicious executables",
            "Block execution of suspicious scripts",
        ],
        "evidence_preservation": [
            "Acquire copies of malicious files before quarantine",
            "Preserve command-line audit logs",
        ],
        "collection_steps": [
            "Collect process execution history from Sysmon/ETW",
            "Analyze command-line arguments of suspicious processes",
        ],
        "further_investigation": [
            "Submit executables to sandbox for dynamic analysis",
            "Correlate execution times with other lateral movement",
        ],
    },
    "Defense Evasion": {
        "containment": [
            "Re-enable tampered security controls",
            "Restore modified audit configurations",
        ],
        "evidence_preservation": [
            "Preserve unaltered copies of tampered logs",
            "Capture hidden artifacts before remediation",
        ],
        "collection_steps": [
            "Check for log clearing events (Event ID 1102/104)",
            "Inspect hidden files, ADS, and packed binaries",
        ],
        "further_investigation": [
            "Analyze timestomped files for true creation dates",
            "Check for process hollowing or DLL side-loading",
        ],
    },
    "Lateral Movement": {
        "containment": [
            "Isolate affected host from network immediately",
            "Block identified lateral movement ports/protocols",
        ],
        "evidence_preservation": [
            "Capture network flow data before isolation",
            "Preserve remote access logs",
        ],
        "collection_steps": [
            "Audit SMB/WinRM/RDP connections from host",
            "Collect authentication logs from domain controllers",
        ],
        "further_investigation": [
            "Map full lateral movement path across environment",
            "Check destination hosts for secondary infections",
        ],
    },
    "Impact": {
        "containment": [
            "Disconnect affected systems from production network",
            "Halt identified destructive processes",
        ],
        "evidence_preservation": [
            "Acquire forensic images of affected drives",
            "Preserve any ransom notes or attacker communications",
        ],
        "collection_steps": [
            "Assess extent of data destruction or encryption",
            "Verify backup integrity for affected systems",
        ],
        "further_investigation": [
            "Determine if data exfiltration preceded destruction",
            "Analyze malware for decryption possibilities",
        ],
    },
    "Privilege Escalation": {
        "containment": [
            "Revoke escalated privileges immediately",
            "Disable compromised high-privilege accounts",
        ],
        "evidence_preservation": [
            "Preserve privilege assignment audit logs",
            "Capture token and privilege state of suspect processes",
        ],
        "collection_steps": [
            "Review privilege assignments and group memberships",
            "Audit token usage for impersonation attacks",
        ],
        "further_investigation": [
            "Analyze exploit vectors used for escalation",
            "Check for kernel-mode rootkit indicators",
        ],
    },
    "Command and Control": {
        "containment": [
            "Block suspicious IPs and domains at perimeter",
            "Sinkhole identified C2 domains",
        ],
        "evidence_preservation": [
            "Capture full PCAP of C2 traffic before blocking",
            "Preserve DNS query logs",
        ],
        "collection_steps": [
            "Analyze network traffic patterns for beaconing",
            "Collect proxy and firewall logs for C2 indicators",
        ],
        "further_investigation": [
            "Decode C2 protocol for command extraction",
            "Identify all hosts communicating with C2 infrastructure",
        ],
    },
    "Exfiltration": {
        "containment": [
            "Block outbound connections to identified destinations",
            "Enable DLP controls on affected endpoints",
        ],
        "evidence_preservation": [
            "Preserve data transfer and upload logs",
            "Capture network flow data showing exfil volume",
        ],
        "collection_steps": [
            "Check data transfer logs for large outbound transfers",
            "Audit outbound connections to cloud storage services",
        ],
        "further_investigation": [
            "Determine scope and sensitivity of exfiltrated data",
            "Check for staged data in temporary directories",
        ],
    },
}

UNIVERSAL_ACTIONS: Dict[str, List[str]] = {
    "containment": [
        "Isolate host from network",
        "Disable compromised accounts",
    ],
    "evidence_preservation": [
        "Acquire forensic images of affected media",
        "Preserve volatile evidence (memory, network state)",
    ],
    "further_investigation": [
        "Correlate findings with SIEM logs",
        "Check for additional indicators of compromise (IOCs)",
    ],
}


# ── MitreMapper ──────────────────────────────────────────────────────────────
class MitreMapper:
    """Orchestrates MITRE ATT&CK mapping for forensic AI predictions.

    Parameters
    ----------
    project_root : str or None
        Absolute path to the DEPI-Project root.  When ``None`` the
        mapper auto-detects by walking up from this file's location.
    """

    def __init__(self, project_root: str = None) -> None:
        if project_root is None:
            project_root = _PROJECT_ROOT_CANDIDATE
        self.project_root: str = project_root
        self.engine = RuleEngine()

    # ── Public API ────────────────────────────────────────────────────────

    def map(
        self,
        category: str,
        prediction_data: dict,
        feature_vector: dict = None,
        parsed_evidence: dict = None,
    ) -> dict:
        """Run the full MITRE mapping pipeline.

        Parameters
        ----------
        category : str
            Pipeline category (``memory`` / ``database`` / ``disk``).
        prediction_data : dict
            Raw prediction JSON loaded from the pipeline's output file.
        feature_vector : dict or None
            Separate feature vector (required for ``memory``, embedded
            in ``prediction_data`` for ``database`` / ``disk``).
        parsed_evidence : dict or None
            Optional parsed forensic evidence for enrichment.

        Returns
        -------
        dict
            Complete MITRE mapping output structure.
        """
        # 1. Normalize prediction to common format
        normalized = self._normalize_prediction(category, prediction_data)

        # 2. Extract / resolve feature vector
        features = self._extract_features(category, prediction_data, feature_vector)

        # 3. Run rule engine
        matches: List[RuleMatch] = self.engine.evaluate(
            category=category,
            feature_vector=features,
            prediction=normalized,
        )

        # 4. Determine risk level
        risk_level = self._determine_risk_level(
            prediction=normalized.get("prediction", "SAFE"),
            anomaly_score=normalized.get("anomaly_score", 0.0),
            techniques=matches,
        )

        # 5. Generate recommendations
        recommendations = self._generate_recommendations(matches)

        # 6. Build and return output
        total_rules = len(self.engine.load_rules(category))

        return self._build_output(
            category=category,
            prediction_data=prediction_data,
            normalized=normalized,
            matches=matches,
            risk_level=risk_level,
            recommendations=recommendations,
            total_rules_evaluated=total_rules,
            parsed_evidence=parsed_evidence,
        )

    # ── Normalization ─────────────────────────────────────────────────────

    def _normalize_prediction(self, category: str, prediction_data: dict) -> dict:
        """Normalize different pipeline outputs to a common format.

        Common format
        ^^^^^^^^^^^^^
        ``{"prediction": "MALICIOUS"|"SAFE", "anomaly_score": float}``

        * ``anomaly_score`` is always *higher = more anomalous*.

        Memory normalization
        ^^^^^^^^^^^^^^^^^^^^
        * ``prediction``: ``normal`` → ``SAFE``, ``anomalous`` → ``MALICIOUS``
        * ``anomaly_score``: raw value (lower = more anomalous) is inverted.

        Database / Disk
        ^^^^^^^^^^^^^^^
        Already in the common format.

        Parameters
        ----------
        category : str
            Pipeline category.
        prediction_data : dict
            Raw prediction output from the pipeline.

        Returns
        -------
        dict
            Normalized prediction data.
        """
        if not isinstance(prediction_data, dict):
            logger.warning("prediction_data is not a dict — using empty defaults")
            return {"prediction": "SAFE", "anomaly_score": 0.0}

        result: Dict[str, Any] = {}

        if category == "memory":
            # Prediction label
            raw_pred = str(prediction_data.get("prediction", "normal")).lower()
            result["prediction"] = "MALICIOUS" if raw_pred == "anomalous" else "SAFE"

            # Anomaly score — memory uses "lower = more anomalous"
            # Invert so that higher = more anomalous.
            raw_score = prediction_data.get("anomaly_score", 0.0)
            try:
                raw_score = float(raw_score)
            except (TypeError, ValueError):
                raw_score = 0.0
            result["anomaly_score"] = round(abs(raw_score), 6)

        else:
            # database / disk — already in target format
            pred = str(prediction_data.get("prediction", "SAFE")).upper()
            result["prediction"] = pred if pred in ("MALICIOUS", "SAFE") else "SAFE"

            score = prediction_data.get("anomaly_score", 0.0)
            try:
                result["anomaly_score"] = round(float(score), 6)
            except (TypeError, ValueError):
                result["anomaly_score"] = 0.0

        return result

    # ── Feature extraction ────────────────────────────────────────────────

    def _extract_features(
        self,
        category: str,
        prediction_data: dict,
        feature_vector: dict = None,
    ) -> dict:
        """Extract the feature vector for rule evaluation.

        * **Memory**: features live in a *separate* file → use
          ``feature_vector`` parameter.
        * **Database / Disk**: features are embedded in
          ``prediction_data["feature_vector"]``.

        Parameters
        ----------
        category : str
            Pipeline category.
        prediction_data : dict
            Raw prediction JSON.
        feature_vector : dict or None
            Explicitly supplied feature vector (used for memory).

        Returns
        -------
        dict
            Feature name → value mapping.
        """
        if category == "memory":
            if feature_vector and isinstance(feature_vector, dict):
                return feature_vector
            logger.warning(
                "Memory category requires a separate feature vector file — "
                "features will be empty"
            )
            return {}

        # database / disk — embedded
        if isinstance(prediction_data, dict):
            embedded = prediction_data.get("feature_vector", {})
            if isinstance(embedded, dict):
                return embedded
            logger.warning("Embedded feature_vector is not a dict — using empty")

        return {}

    # ── Risk level ────────────────────────────────────────────────────────

    def _determine_risk_level(
        self,
        prediction: str,
        anomaly_score: float,
        techniques: List[RuleMatch],
    ) -> str:
        """Classify the overall risk level.

        Thresholds (evaluated top-down, first match wins):

        * **CRITICAL**: prediction is MALICIOUS AND
          (anomaly_score > 0.6 OR any Critical technique matched)
        * **HIGH**: prediction is MALICIOUS AND anomaly_score > 0.4
        * **MEDIUM**: prediction is MALICIOUS OR anomaly_score > 0.3
        * **LOW**: anomaly_score > 0.2 OR any techniques matched
        * **SAFE**: otherwise

        Parameters
        ----------
        prediction : str
            Normalized prediction label (``MALICIOUS`` or ``SAFE``).
        anomaly_score : float
            Normalized anomaly score (higher = worse).
        techniques : List[RuleMatch]
            Matched rule results.

        Returns
        -------
        str
            One of ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``, ``SAFE``.
        """
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

    # ── Recommendations ───────────────────────────────────────────────────

    def _generate_recommendations(self, techniques: List[RuleMatch]) -> List[dict]:
        """Build actionable recommendation dicts for each matched technique.

        Each recommendation includes tactic-specific actions plus
        universal actions that apply to every incident.

        Parameters
        ----------
        techniques : List[RuleMatch]
            List of matched rules.

        Returns
        -------
        List[dict]
            Priority-ordered list of recommendation dicts.
        """
        if not techniques:
            return []

        severity_priority = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}

        recommendations: List[dict] = []
        for match in techniques:
            rule = match.rule
            tactic = rule.mitre_tactic
            priority = severity_priority.get(match.severity, 4)

            # Start from tactic-specific actions (if available)
            tactic_actions = TACTIC_RECOMMENDATIONS.get(tactic, {})

            actions: Dict[str, List[str]] = {
                "containment": list(
                    tactic_actions.get("containment", UNIVERSAL_ACTIONS["containment"])
                ),
                "evidence_preservation": list(
                    tactic_actions.get(
                        "evidence_preservation",
                        UNIVERSAL_ACTIONS["evidence_preservation"],
                    )
                ),
                "collection_steps": list(
                    tactic_actions.get("collection_steps", [])
                ),
                "further_investigation": list(
                    tactic_actions.get(
                        "further_investigation",
                        UNIVERSAL_ACTIONS["further_investigation"],
                    )
                ),
            }

            # Merge universal actions (avoiding duplicates)
            for key, universal in UNIVERSAL_ACTIONS.items():
                existing = set(actions.get(key, []))
                for action in universal:
                    if action not in existing:
                        actions[key].append(action)

            recommendations.append(
                {
                    "priority": priority,
                    "technique_id": rule.mitre_technique_id,
                    "technique_name": rule.mitre_technique_name,
                    "tactic": tactic,
                    "actions": actions,
                }
            )

        # Sort by priority (Critical first)
        recommendations.sort(key=lambda r: r["priority"])

        # Re-number priorities sequentially
        for idx, rec in enumerate(recommendations, start=1):
            rec["priority"] = idx

        return recommendations

    # ── Output builder ────────────────────────────────────────────────────

    def _build_output(
        self,
        category: str,
        prediction_data: dict,
        normalized: dict,
        matches: List[RuleMatch],
        risk_level: str,
        recommendations: list,
        total_rules_evaluated: int,
        parsed_evidence: dict = None,
    ) -> dict:
        """Assemble the final ``mitre_mapping.json`` structure.

        Parameters
        ----------
        category : str
            Pipeline category.
        prediction_data : dict
            Original (unnormalized) prediction data.
        normalized : dict
            Normalized prediction values.
        matches : List[RuleMatch]
            All matched rules.
        risk_level : str
            Computed risk level string.
        recommendations : list
            Generated recommendation dicts.
        total_rules_evaluated : int
            Total number of rules that were evaluated.
        parsed_evidence : dict or None
            Optional parsed evidence payload.

        Returns
        -------
        dict
            Complete output structure for serialization.
        """
        now = datetime.now(timezone.utc)
        timestamp_str = now.strftime("%Y%m%d_%H%M%S")

        prediction_label = normalized.get("prediction", "SAFE")
        anomaly_score = normalized.get("anomaly_score", 0.0)

        # Interpretation string
        interpretations = {
            "CRITICAL": "CRITICAL — Highly Anomalous",
            "HIGH": "HIGH — Significant Anomaly Detected",
            "MEDIUM": "MEDIUM — Moderate Anomaly Detected",
            "LOW": "LOW — Minor Anomaly Detected",
            "SAFE": "NORMAL — Safe Activity",
        }
        interpretation = interpretations.get(risk_level, f"{risk_level} — Unknown")

        # Auto-detect tool from prediction data
        tool = prediction_data.get("audit_tool") or prediction_data.get("tool") or None

        # Severity counters
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        tactics_involved: List[str] = []

        techniques_list: List[dict] = []
        for match in matches:
            rule = match.rule
            severity_counts[match.severity] = severity_counts.get(match.severity, 0) + 1

            if rule.mitre_tactic not in tactics_involved:
                tactics_involved.append(rule.mitre_tactic)

            techniques_list.append(
                {
                    "rule_id": rule.rule_id,
                    "id": rule.mitre_technique_id,
                    "name": rule.mitre_technique_name,
                    "tactic": rule.mitre_tactic,
                    "confidence": match.confidence,
                    "severity": match.severity,
                    "description": rule.description,
                    "matched_conditions": match.matched_conditions,
                    "recommendation": rule.recommendation,
                }
            )

        output: Dict[str, Any] = {
            "case_id": f"CASE-{timestamp_str}",
            "category": category,
            "tool": tool,
            "analysis_timestamp": now.isoformat(),
            "prediction": prediction_label,
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

        if parsed_evidence is not None:
            output["parsed_evidence_summary"] = {
                "source": parsed_evidence.get("source"),
                "total_entries": parsed_evidence.get("total_entries"),
            }

        return output

    # ── File I/O helpers ──────────────────────────────────────────────────

    @staticmethod
    def load_json(path: str) -> dict:
        """Safely load a JSON file.

        Parameters
        ----------
        path : str
            Absolute or relative path to the JSON file.

        Returns
        -------
        dict
            Parsed JSON content, or an empty dict on failure.
        """
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
            logger.warning("JSON at %s is not a dict — returning empty", path)
            return {}
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load JSON from %s: %s", path, exc)
            return {}

    @staticmethod
    def save_json(data: dict, path: str) -> None:
        """Write a dict to a JSON file.

        Parameters
        ----------
        data : dict
            Data to serialize.
        path : str
            Output file path.
        """
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
        logger.info("Saved mapping to %s", path)


# ── CLI ──────────────────────────────────────────────────────────────────────
def main() -> None:
    """Command-line entry-point for the MITRE mapper."""
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Mapping Engine — map forensic predictions to ATT&CK techniques.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python mapper.py --category disk --prediction disk/prediction/disk_prediction.json\n"
            "  python mapper.py --category memory --prediction memory/inference/prediction.json "
            "--features memory/features/memory_feature_vector.json\n"
        ),
    )
    parser.add_argument(
        "--category",
        required=True,
        choices=["memory", "database", "disk"],
        help="Pipeline category to map.",
    )
    parser.add_argument(
        "--prediction",
        required=True,
        help="Path to the prediction JSON file.",
    )
    parser.add_argument(
        "--features",
        default=None,
        help="Path to a separate feature vector JSON (required for memory).",
    )
    parser.add_argument(
        "--evidence",
        default=None,
        help="Path to parsed evidence JSON (optional).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output directory (default: core/mitre/).",
    )

    args = parser.parse_args()

    # ── Resolve paths ────────────────────────────────────────────────────
    mapper = MitreMapper()

    prediction_data = MitreMapper.load_json(args.prediction)
    if not prediction_data:
        print(f"[ERROR] Could not load prediction file: {args.prediction}", file=sys.stderr)
        sys.exit(1)

    feature_vector: Optional[dict] = None
    if args.features:
        feature_vector = MitreMapper.load_json(args.features)
        if not feature_vector:
            print(f"[ERROR] Could not load feature file: {args.features}", file=sys.stderr)
            sys.exit(1)
    elif args.category == "memory":
        print(
            "[WARN] Memory category requires --features; "
            "rule evaluation will have no feature data.",
            file=sys.stderr,
        )

    parsed_evidence: Optional[dict] = None
    if args.evidence:
        parsed_evidence = MitreMapper.load_json(args.evidence)

    # ── Run mapping ──────────────────────────────────────────────────────
    result = mapper.map(
        category=args.category,
        prediction_data=prediction_data,
        feature_vector=feature_vector,
        parsed_evidence=parsed_evidence,
    )

    # ── Save output ──────────────────────────────────────────────────────
    output_dir = args.output or _THIS_DIR
    output_path = os.path.join(output_dir, "mitre_mapping.json")
    MitreMapper.save_json(result, output_path)

    # ── Print summary ────────────────────────────────────────────────────
    summary = result.get("summary", {})
    print("=" * 60)
    print("MITRE ATT&CK Mapping Complete")
    print("=" * 60)
    print(f"  Category        : {result['category']}")
    print(f"  Prediction      : {result['prediction']}")
    print(f"  Anomaly Score   : {result['anomaly_score']}")
    print(f"  Risk Level      : {result['risk_level']}")
    print(f"  Interpretation  : {result['interpretation']}")
    print(f"  Rules Evaluated : {summary.get('total_rules_evaluated', 0)}")
    print(f"  Rules Matched   : {summary.get('total_rules_matched', 0)}")
    print(f"    Critical      : {summary.get('critical_count', 0)}")
    print(f"    High          : {summary.get('high_count', 0)}")
    print(f"    Medium        : {summary.get('medium_count', 0)}")
    print(f"    Low           : {summary.get('low_count', 0)}")

    tactics = summary.get("tactics_involved", [])
    if tactics:
        print(f"  Tactics         : {', '.join(tactics)}")

    print(f"  Output          : {output_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
