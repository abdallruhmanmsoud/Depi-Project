"""
report_generator.py — Digital Forensics Report Generator
=========================================================

Generates comprehensive forensic reports in Markdown, HTML, and JSON formats.

Input:
    - Prediction data (from any AI pipeline)
    - Feature vector
    - MITRE ATT&CK mapping output (from mapper.py)
    - Parsed evidence (optional)

Output:
    - case_report.md
    - case_report.html
    - case_report.json

Usage:
    python core/reporting/report_generator.py --mapping core/mitre/mitre_mapping.json
    python core/reporting/report_generator.py --mapping core/mitre/mitre_mapping.json --prediction disk/prediction/disk_prediction.json
"""

import json
import os
import sys
import html
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(SCRIPT_DIR, "templates")
REPORTS_DIR   = os.path.join(SCRIPT_DIR, "reports")
CORE_DIR      = os.path.dirname(SCRIPT_DIR)
PROJECT_ROOT  = os.path.dirname(CORE_DIR)


# ═══════════════════════════════════════════════════════════════════════════════
#  FEATURE SIGNIFICANCE CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

# Features considered suspicious at high values, grouped by category
SUSPICIOUS_FEATURES = {
    "memory": {
        "mf_total_findings":              ("Malfind detections", 5),
        "mf_rwx_count":                   ("RWX memory regions", 3),
        "mf_non_jit_rwx_count":           ("Non-JIT RWX regions", 0),
        "proc_powershell_count":          ("PowerShell processes", 0),
        "cmd_encoded_command_count":      ("Encoded commands", 0),
        "cmd_base64_count":              ("Base64 in command lines", 5),
        "cmd_suspicious_total":           ("Suspicious commands", 3),
        "handle_lsass_handle_count":      ("LSASS handle access", 5),
        "priv_debug_enabled":             ("Debug privilege enabled", 10),
        "priv_high_risk_enabled_ratio":   ("High-risk privilege ratio", 0.15),
        "dll_suspicious_path_count":      ("Suspicious DLL paths", 1),
        "net_external_count":             ("External connections", 5),
        "proc_orphan_count":              ("Orphaned processes", 3),
        "proc_parent_mismatch_count":     ("Parent PID mismatches", 1),
        "cross_anomaly_composite_score":  ("Composite anomaly score", 50),
        "handle_persistence_key_count":   ("Persistence registry keys", 100),
        "proc_zero_thread_count":         ("Zero-thread processes", 3),
        "dll_non_system_count":           ("Non-system DLLs", 50),
    },
    "database": {
        "delete_count":                   ("DELETE operations", 5000),
        "drop_table_count":               ("DROP TABLE operations", 10),
        "drop_database_count":            ("DROP DATABASE operations", 0),
        "create_user_count":              ("User creations", 50),
        "grant_count":                    ("GRANT operations", 1000),
        "privilege_escalation_events":    ("Privilege escalations", 500),
        "error_event_count":              ("Error events", 50),
        "destructive_operations":         ("Destructive operations", 5000),
        "schema_modification_events":     ("Schema modifications", 1000),
        "total_configuration_events":     ("Configuration changes", 500),
        "rollback_count":                 ("Transaction rollbacks", 100),
        "overall_database_activity_score":("Overall activity score", 100000),
        "authentication_changes":         ("Authentication changes", 500),
        "update_count":                   ("UPDATE operations", 50000),
        "insert_count":                   ("INSERT operations", 100000),
    },
    "disk": {
        "executables_in_temp":            ("Executables in Temp", 10),
        "executables_in_downloads":       ("Executables in Downloads", 20),
        "executables_on_desktop":         ("Executables on Desktop", 50),
        "double_extension_count":         ("Double-extension files", 100),
        "hidden_executables":             ("Hidden executables", 0),
        "deleted_executables":            ("Deleted executables", 5),
        "persistence_indicators":         ("Persistence indicators", 100),
        "scripts_in_suspicious_dirs":     ("Scripts in suspicious dirs", 5),
        "creation_bursts":                ("File creation bursts", 20),
        "deletion_bursts":                ("File deletion bursts", 5),
        "deletion_ratio":                 ("Deletion ratio", 0.15),
        "night_activity_ratio":           ("Night activity ratio", 0.5),
        "overall_disk_risk_score":        ("Overall disk risk score", 100000),
        "execution_risk_score":           ("Execution risk score", 10000),
        "persistence_score":              ("Persistence score", 5000),
        "deleted_inode_ratio":            ("Deleted inode ratio", 0.1),
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
#  IOC EXTRACTION CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

IOC_FEATURE_MAP = {
    "memory": {
        "Process":   ["proc_powershell_count", "proc_cmd_count", "proc_lolbin_count",
                      "proc_script_engine_count", "proc_browser_count"],
        "DLL":       ["dll_suspicious_path_count", "dll_non_system_count"],
        "Registry":  ["handle_persistence_key_count"],
        "Network":   ["net_external_count", "net_unique_remote_hosts",
                      "net_uncommon_port_count"],
        "Privilege": ["priv_debug_enabled", "priv_create_token_enabled"],
    },
    "database": {
        "User":      ["create_user_count", "drop_user_count"],
        "Table":     ["drop_table_count", "create_table_count"],
        "Database":  ["drop_database_count", "create_database_count"],
        "Command":   ["grant_count", "revoke_count"],
    },
    "disk": {
        "Executable": ["executables_in_temp", "executables_in_downloads",
                       "executables_on_desktop", "deleted_executables",
                       "hidden_executables"],
        "File":       ["double_extension_count", "scripts_in_suspicious_dirs"],
        "Registry":   ["persistence_indicators", "ext_lnk_count"],
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
#  ForensicReportGenerator
# ═══════════════════════════════════════════════════════════════════════════════

class ForensicReportGenerator:
    """
    Generates comprehensive Digital Forensics reports in
    Markdown, HTML, and JSON formats.
    """

    def __init__(self, output_dir: str = None, templates_dir: str = None):
        self.output_dir    = output_dir or REPORTS_DIR
        self.templates_dir = templates_dir or TEMPLATES_DIR
        os.makedirs(self.output_dir, exist_ok=True)

    # ─── Main Entry Point ─────────────────────────────────────────────────────

    def generate(
        self,
        mitre_mapping:   dict,
        prediction_data: dict = None,
        feature_vector:  dict = None,
        parsed_evidence: dict = None,
        case_id:         str  = None,
    ) -> Dict[str, str]:
        """
        Generate all report formats.

        Args:
            mitre_mapping:   Output from mapper.py
            prediction_data: Raw prediction JSON from the AI pipeline
            feature_vector:  Feature vector dict (if not in prediction_data)
            parsed_evidence: Parsed evidence dict (optional)
            case_id:         Override case ID (auto-generated if not given)

        Returns:
            dict with paths to generated report files
        """
        # Merge data sources
        report_data = self._prepare_report_data(
            mitre_mapping, prediction_data, feature_vector, parsed_evidence, case_id
        )

        # Generate all formats
        paths = {}
        paths["json"] = self._generate_json(report_data)
        paths["md"]   = self._generate_markdown(report_data)
        paths["html"] = self._generate_html(report_data)

        return paths

    # ─── Data Preparation ─────────────────────────────────────────────────────

    def _prepare_report_data(
        self,
        mitre_mapping:   dict,
        prediction_data: dict = None,
        feature_vector:  dict = None,
        parsed_evidence: dict = None,
        case_id:         str  = None,
    ) -> dict:
        """Build a unified report data structure from all inputs."""

        category = mitre_mapping.get("category", "unknown")
        prediction_data = prediction_data or {}
        feature_vector  = feature_vector or {}

        # Extract features from prediction if not separate
        if not feature_vector and "feature_vector" in prediction_data:
            feature_vector = prediction_data["feature_vector"]

        # Case metadata
        now = datetime.now(timezone.utc)
        cid = case_id or mitre_mapping.get("case_id", f"CASE-{now.strftime('%Y%m%d-%H%M%S')}")
        pred_time = prediction_data.get("prediction_time_ms", mitre_mapping.get("prediction_time_ms", 0))
        tool = (prediction_data.get("audit_tool")
                or mitre_mapping.get("tool")
                or prediction_data.get("case_root")
                or "N/A")

        # Prediction info
        prediction   = mitre_mapping.get("prediction", prediction_data.get("prediction", "UNKNOWN"))
        risk_level   = mitre_mapping.get("risk_level", "UNKNOWN")
        anomaly_score = mitre_mapping.get("anomaly_score", prediction_data.get("anomaly_score", 0))
        interpretation = (mitre_mapping.get("interpretation")
                         or prediction_data.get("interpretation", ""))

        # Techniques
        techniques = mitre_mapping.get("techniques", [])
        recommendations = mitre_mapping.get("recommendations", [])
        summary = mitre_mapping.get("summary", {})

        # Build feature highlights
        feature_highlights = self._rank_features(category, feature_vector)

        # Build IOC list
        iocs = self._extract_iocs(category, feature_vector, prediction_data)

        # Build evidence summary
        evidence_items = self._build_evidence_summary(
            category, feature_vector, techniques, prediction, anomaly_score
        )

        # Build timeline
        timeline = self._build_timeline(
            category, feature_vector, prediction_data, now
        )

        # Build executive summary
        exec_summary = self._build_executive_summary(
            category, prediction, risk_level, anomaly_score,
            len(techniques), summary
        )

        # Build conclusion
        conclusion = self._build_conclusion(
            category, prediction, risk_level, len(techniques), summary
        )

        # Compute overall confidence
        confidences = [t.get("confidence", 0) for t in techniques]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0

        return {
            "case_id":           cid,
            "category":          category,
            "tool":              tool,
            "analysis_date":     now.isoformat(),
            "processing_time":   f"{pred_time:.2f} ms" if pred_time else "N/A",
            "prediction":        prediction,
            "risk_level":        risk_level,
            "anomaly_score":     anomaly_score,
            "confidence":        round(avg_confidence, 4),
            "interpretation":    interpretation,
            "executive_summary": exec_summary,
            "evidence_items":    evidence_items,
            "feature_highlights": feature_highlights,
            "techniques":        techniques,
            "iocs":              iocs,
            "timeline":          timeline,
            "recommendations":   recommendations,
            "conclusion":        conclusion,
            "summary":           summary,
            "feature_vector":    feature_vector,
            "generation_timestamp": now.isoformat(),
        }

    # ─── Feature Ranking ──────────────────────────────────────────────────────

    def _rank_features(
        self, category: str, feature_vector: dict
    ) -> List[Dict[str, Any]]:
        """Rank features by how much they exceed their suspicious thresholds."""
        suspicious = SUSPICIOUS_FEATURES.get(category, {})
        ranked = []

        for feat, (label, threshold) in suspicious.items():
            value = feature_vector.get(feat)
            if value is None:
                continue

            try:
                value = float(value)
            except (ValueError, TypeError):
                continue

            if threshold == 0:
                if value > 0:
                    ratio = value * 10  # strong signal if threshold is 0
                else:
                    continue
            else:
                ratio = value / threshold if threshold > 0 else 0

            if ratio >= 1.0:
                significance = "CRITICAL" if ratio >= 5 else "HIGH" if ratio >= 2 else "ELEVATED"
                ranked.append({
                    "feature":      feat,
                    "label":        label,
                    "value":        value,
                    "threshold":    threshold,
                    "ratio":        round(ratio, 2),
                    "significance": significance,
                })

        ranked.sort(key=lambda x: x["ratio"], reverse=True)
        return ranked[:20]  # Top 20

    # ─── IOC Extraction ───────────────────────────────────────────────────────

    def _extract_iocs(
        self, category: str, feature_vector: dict, prediction_data: dict
    ) -> List[Dict[str, str]]:
        """Extract Indicators of Compromise from features and prediction data."""
        iocs = []
        ioc_map = IOC_FEATURE_MAP.get(category, {})

        for ioc_type, features in ioc_map.items():
            for feat in features:
                val = feature_vector.get(feat)
                if val is not None and val != 0:
                    iocs.append({
                        "type":    ioc_type,
                        "feature": feat,
                        "value":   str(val),
                        "detail":  f"{feat} = {val}",
                    })

        # Add risk flags from disk pipeline
        risk_flags = prediction_data.get("risk_flags", [])
        for flag in risk_flags:
            iocs.append({
                "type":    "Risk Flag",
                "feature": "risk_flag",
                "value":   flag,
                "detail":  flag,
            })

        # Add categorical features as IOCs
        cats = prediction_data.get("categorical_features", {})
        for key, val in cats.items():
            if val:
                ioc_type = "Database" if "database" in key else "File" if "filesystem" in key else "Entity"
                iocs.append({
                    "type":    ioc_type,
                    "feature": key,
                    "value":   str(val),
                    "detail":  f"{key}: {val}",
                })

        return iocs

    # ─── Evidence Summary ─────────────────────────────────────────────────────

    def _build_evidence_summary(
        self,
        category:       str,
        feature_vector: dict,
        techniques:     list,
        prediction:     str,
        anomaly_score:  float,
    ) -> List[Dict[str, str]]:
        """Build ranked evidence items explaining why the AI made its decision."""
        items = []

        # Primary verdict explanation
        if prediction in ("MALICIOUS", "anomalous"):
            items.append({
                "rank":   1,
                "level":  "critical",
                "title":  "AI Verdict: Anomalous Activity Detected",
                "detail": (f"The Isolation Forest model classified this case as {prediction} "
                          f"with an anomaly score of {anomaly_score:.4f}. "
                          f"Higher anomaly scores indicate greater deviation from normal patterns."),
            })
        else:
            items.append({
                "rank":   1,
                "level":  "low",
                "title":  "AI Verdict: Normal Activity",
                "detail": (f"The Isolation Forest model classified this case as {prediction} "
                          f"with an anomaly score of {anomaly_score:.4f}. "
                          f"The activity falls within expected baseline parameters."),
            })

        # Add evidence from matched techniques
        for i, tech in enumerate(techniques[:5], start=2):
            severity = tech.get("severity", "Medium").lower()
            level = "critical" if severity == "critical" else "high" if severity == "high" else "medium"
            conditions = tech.get("matched_conditions", [])
            cond_text = ", ".join(
                f"{c.get('feature', '?')} {c.get('operator', '?')} {c.get('expected', '?')} (actual: {c.get('actual', '?')})"
                for c in conditions
            ) if conditions else tech.get("description", "")

            items.append({
                "rank":   i,
                "level":  level,
                "title":  f"MITRE {tech.get('id', '?')}: {tech.get('name', '?')}",
                "detail": f"Tactic: {tech.get('tactic', '?')}. "
                         f"Confidence: {tech.get('confidence', 0):.0%}. "
                         f"Evidence: {cond_text}",
            })

        return items

    # ─── Timeline ─────────────────────────────────────────────────────────────

    def _build_timeline(
        self,
        category:        str,
        feature_vector:  dict,
        prediction_data: dict,
        analysis_time:   datetime,
    ) -> List[Dict[str, str]]:
        """Build a timeline summary of forensic activity."""
        timeline = []

        # Time-based features
        if category == "disk":
            earliest = feature_vector.get("earliest_timestamp")
            latest   = feature_vector.get("latest_timestamp")
            duration = feature_vector.get("timeline_duration")
            creation_bursts  = feature_vector.get("creation_bursts", 0)
            deletion_bursts  = feature_vector.get("deletion_bursts", 0)
            mod_bursts       = feature_vector.get("modification_bursts", 0)
            peak_hour        = feature_vector.get("peak_activity_hour")
            peak_day         = feature_vector.get("peak_activity_day")

            if earliest:
                try:
                    ts = datetime.fromtimestamp(earliest, tz=timezone.utc)
                    timeline.append({
                        "timestamp": ts.isoformat(),
                        "event":     "Earliest file activity detected",
                    })
                except (OSError, ValueError):
                    pass

            if latest:
                try:
                    ts = datetime.fromtimestamp(latest, tz=timezone.utc)
                    timeline.append({
                        "timestamp": ts.isoformat(),
                        "event":     "Latest file activity detected",
                    })
                except (OSError, ValueError):
                    pass

            if duration:
                days = int(duration) // 86400
                timeline.append({
                    "timestamp": "Duration",
                    "event":     f"Activity spans {days:,} days ({int(duration):,} seconds)",
                })

            if creation_bursts > 0:
                timeline.append({
                    "timestamp": "Burst Pattern",
                    "event":     f"{creation_bursts} file creation bursts detected (possible staging or deployment)",
                })

            if deletion_bursts > 0:
                timeline.append({
                    "timestamp": "Burst Pattern",
                    "event":     f"{deletion_bursts} file deletion bursts detected (possible anti-forensics)",
                })

            if mod_bursts > 0:
                timeline.append({
                    "timestamp": "Burst Pattern",
                    "event":     f"{mod_bursts} file modification bursts detected",
                })

            if peak_hour is not None:
                day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
                day_name  = day_names[peak_day] if peak_day is not None and 0 <= peak_day < 7 else "N/A"
                timeline.append({
                    "timestamp": "Peak Activity",
                    "event":     f"Peak activity at hour {peak_hour}:00, day: {day_name}",
                })

        elif category == "database":
            first_ts = feature_vector.get("first_timestamp")
            last_ts  = feature_vector.get("last_timestamp")
            duration = feature_vector.get("activity_duration")

            if first_ts:
                try:
                    ts = datetime.fromtimestamp(first_ts, tz=timezone.utc)
                    timeline.append({
                        "timestamp": ts.isoformat(),
                        "event":     "First database event recorded",
                    })
                except (OSError, ValueError):
                    pass

            if last_ts:
                try:
                    ts = datetime.fromtimestamp(last_ts, tz=timezone.utc)
                    timeline.append({
                        "timestamp": ts.isoformat(),
                        "event":     "Last database event recorded",
                    })
                except (OSError, ValueError):
                    pass

            if duration:
                hours = int(duration) // 3600
                mins  = (int(duration) % 3600) // 60
                timeline.append({
                    "timestamp": "Duration",
                    "event":     f"Activity spans {hours}h {mins}m ({int(duration):,} seconds)",
                })

            total_events = feature_vector.get("total_events", 0)
            if total_events:
                timeline.append({
                    "timestamp": "Volume",
                    "event":     f"{total_events:,} total database events processed",
                })

        elif category == "memory":
            timeline.append({
                "timestamp": analysis_time.isoformat(),
                "event":     "Memory image analysis performed",
            })

            proc_count = feature_vector.get("proc_total_count", 0)
            if proc_count:
                timeline.append({
                    "timestamp": "Snapshot",
                    "event":     f"{proc_count} processes found in memory at time of acquisition",
                })

            net_count = feature_vector.get("net_total_connections", 0)
            if net_count > 0:
                timeline.append({
                    "timestamp": "Snapshot",
                    "event":     f"{net_count} active network connections at time of acquisition",
                })

        # Add prediction timestamp
        predicted_at = prediction_data.get("predicted_at")
        if predicted_at:
            timeline.append({
                "timestamp": predicted_at,
                "event":     "AI prediction engine executed",
            })

        timeline.append({
            "timestamp": analysis_time.isoformat(),
            "event":     "MITRE ATT&CK mapping and report generation completed",
        })

        return timeline

    # ─── Executive Summary ────────────────────────────────────────────────────

    def _build_executive_summary(
        self,
        category:      str,
        prediction:    str,
        risk_level:    str,
        anomaly_score: float,
        tech_count:    int,
        summary:       dict,
    ) -> str:
        """Generate a high-level executive summary paragraph."""
        category_label = category.title()

        if prediction in ("MALICIOUS", "anomalous"):
            verdict = (
                f"The {category_label} Forensics AI pipeline has classified this case as "
                f"<strong>{prediction.upper()}</strong> with a risk level of "
                f"<strong>{risk_level}</strong> and an anomaly score of "
                f"<strong>{anomaly_score:.4f}</strong>."
            )
        else:
            verdict = (
                f"The {category_label} Forensics AI pipeline has classified this case as "
                f"<strong>{prediction.upper()}</strong>. The anomaly score of "
                f"<strong>{anomaly_score:.4f}</strong> falls within normal parameters."
            )

        if tech_count > 0:
            tactics = summary.get("tactics_involved", [])
            tactics_str = ", ".join(tactics) if tactics else "multiple tactics"
            technique_desc = (
                f" The MITRE ATT&CK mapping engine identified <strong>{tech_count}</strong> "
                f"matching techniques across the following tactics: {tactics_str}."
            )
            critical = summary.get("critical_count", 0)
            high     = summary.get("high_count", 0)
            if critical > 0:
                technique_desc += (
                    f" Of these, <strong>{critical}</strong> are rated Critical severity, "
                    f"requiring immediate investigation and containment."
                )
            elif high > 0:
                technique_desc += (
                    f" Of these, <strong>{high}</strong> are rated High severity."
                )
        else:
            technique_desc = (
                " No MITRE ATT&CK techniques matched the observed indicators. "
                "The activity appears to be within normal operational parameters."
            )

        return verdict + technique_desc

    # ─── Conclusion ───────────────────────────────────────────────────────────

    def _build_conclusion(
        self,
        category:    str,
        prediction:  str,
        risk_level:  str,
        tech_count:  int,
        summary:     dict,
    ) -> str:
        """Generate a forensic conclusion paragraph."""
        category_label = category.title()

        if prediction in ("MALICIOUS", "anomalous"):
            base = (
                f"<p>Based on the automated analysis of {category_label.lower()} forensic evidence, "
                f"this case exhibits <strong>anomalous activity</strong> consistent with potential "
                f"malicious behavior. The AI model detected significant deviations from baseline "
                f"patterns, and {tech_count} MITRE ATT&CK techniques were identified in the evidence.</p>"
            )
            if risk_level in ("CRITICAL", "HIGH"):
                base += (
                    f"<p>The risk assessment is <strong>{risk_level}</strong>. "
                    f"Immediate containment actions are recommended. All volatile evidence should be "
                    f"preserved before any remediation steps are taken. A manual review by a qualified "
                    f"forensic analyst is strongly advised to confirm these automated findings.</p>"
                )
            else:
                base += (
                    f"<p>The risk assessment is <strong>{risk_level}</strong>. "
                    f"While the findings warrant attention, the overall threat level is moderate. "
                    f"A manual review is recommended to determine the appropriate response.</p>"
                )
        else:
            base = (
                f"<p>Based on the automated analysis of {category_label.lower()} forensic evidence, "
                f"this case appears to represent <strong>normal operational activity</strong>. "
                f"The AI model did not detect significant deviations from baseline patterns.</p>"
            )
            if tech_count > 0:
                base += (
                    f"<p>However, {tech_count} MITRE ATT&CK techniques were matched based on "
                    f"feature thresholds. These may represent benign operational patterns that "
                    f"coincidentally match threat indicators. Manual review is recommended.</p>"
                )
            else:
                base += (
                    "<p>No MITRE ATT&CK techniques were matched, confirming the AI assessment. "
                    "No immediate action is required, but routine monitoring should continue.</p>"
                )

        return base

    # ═══════════════════════════════════════════════════════════════════════════
    #  JSON REPORT
    # ═══════════════════════════════════════════════════════════════════════════

    def _generate_json(self, data: dict) -> str:
        """Generate the JSON report file."""
        report = {
            "report_version":    "1.0.0",
            "case_information": {
                "case_id":        data["case_id"],
                "category":       data["category"],
                "tool":           data["tool"],
                "analysis_date":  data["analysis_date"],
                "processing_time": data["processing_time"],
            },
            "ai_assessment": {
                "prediction":     data["prediction"],
                "risk_level":     data["risk_level"],
                "anomaly_score":  data["anomaly_score"],
                "confidence":     data["confidence"],
                "interpretation": data["interpretation"],
            },
            "evidence_summary":   data["evidence_items"],
            "feature_highlights": data["feature_highlights"],
            "mitre_mapping": {
                "techniques_matched": len(data["techniques"]),
                "techniques":         data["techniques"],
                "summary":            data["summary"],
            },
            "indicators_of_compromise": data["iocs"],
            "timeline":          data["timeline"],
            "recommendations":   data["recommendations"],
            "conclusion":        _strip_html(data["conclusion"]),
            "generation_timestamp": data["generation_timestamp"],
        }

        path = os.path.join(self.output_dir, "case_report.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)

        return path

    # ═══════════════════════════════════════════════════════════════════════════
    #  MARKDOWN REPORT
    # ═══════════════════════════════════════════════════════════════════════════

    def _generate_markdown(self, data: dict) -> str:
        """Generate the Markdown report file."""
        lines = []

        # Title
        lines.append(f"# Digital Forensics Report — {data['case_id']}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 1. Case Information
        lines.append("## 1. Case Information")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **Case ID** | {data['case_id']} |")
        lines.append(f"| **Category** | {data['category'].title()} |")
        lines.append(f"| **Tool** | {data['tool']} |")
        lines.append(f"| **Analysis Date** | {data['analysis_date']} |")
        lines.append(f"| **Processing Time** | {data['processing_time']} |")
        lines.append("")

        # 2. Executive Summary
        lines.append("---")
        lines.append("")
        lines.append("## 2. Executive Summary")
        lines.append("")
        lines.append(_strip_html(data["executive_summary"]))
        lines.append("")

        # 3. AI Assessment
        lines.append("---")
        lines.append("")
        lines.append("## 3. AI Assessment")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| **Prediction** | {data['prediction']} |")
        lines.append(f"| **Risk Level** | {data['risk_level']} |")
        lines.append(f"| **Confidence** | {data['confidence']:.2%} |")
        lines.append(f"| **Anomaly Score** | {data['anomaly_score']:.4f} |")
        lines.append(f"| **Interpretation** | {data['interpretation']} |")
        lines.append("")

        # 4. Evidence Summary
        lines.append("---")
        lines.append("")
        lines.append("## 4. Evidence Summary")
        lines.append("")
        for item in data["evidence_items"]:
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                item["level"], "⚪"
            )
            lines.append(f"### {severity_icon} #{item['rank']} — {item['title']}")
            lines.append("")
            lines.append(item["detail"])
            lines.append("")

        # 5. Feature Highlights
        lines.append("---")
        lines.append("")
        lines.append("## 5. Feature Highlights")
        lines.append("")
        if data["feature_highlights"]:
            lines.append("| Rank | Feature | Value | Threshold | Ratio | Significance |")
            lines.append("|------|---------|-------|-----------|-------|-------------|")
            for i, fh in enumerate(data["feature_highlights"], 1):
                lines.append(
                    f"| {i} | {fh['label']} | {fh['value']} | {fh['threshold']} | "
                    f"{fh['ratio']}x | {fh['significance']} |"
                )
            lines.append("")
        else:
            lines.append("No features exceeded suspicious thresholds.")
            lines.append("")

        # 6. MITRE ATT&CK Mapping
        lines.append("---")
        lines.append("")
        lines.append("## 6. MITRE ATT&CK Mapping")
        lines.append("")
        if data["techniques"]:
            lines.append("| # | ID | Technique | Tactic | Confidence | Severity |")
            lines.append("|---|-----|-----------|--------|------------|----------|")
            for i, tech in enumerate(data["techniques"], 1):
                lines.append(
                    f"| {i} | {tech.get('id', 'N/A')} | {tech.get('name', 'N/A')} | "
                    f"{tech.get('tactic', 'N/A')} | {tech.get('confidence', 0):.0%} | "
                    f"{tech.get('severity', 'N/A')} |"
                )
            lines.append("")
        else:
            lines.append("No MITRE ATT&CK techniques matched.")
            lines.append("")

        # 7. Indicators of Compromise
        lines.append("---")
        lines.append("")
        lines.append("## 7. Indicators of Compromise")
        lines.append("")
        if data["iocs"]:
            lines.append("| Type | Indicator | Value |")
            lines.append("|------|-----------|-------|")
            for ioc in data["iocs"]:
                lines.append(f"| {ioc['type']} | {ioc['feature']} | {ioc['value']} |")
            lines.append("")
        else:
            lines.append("No indicators of compromise identified.")
            lines.append("")

        # 8. Timeline Summary
        lines.append("---")
        lines.append("")
        lines.append("## 8. Timeline Summary")
        lines.append("")
        if data["timeline"]:
            for entry in data["timeline"]:
                lines.append(f"- **{entry['timestamp']}** — {entry['event']}")
            lines.append("")
        else:
            lines.append("No timeline data available.")
            lines.append("")

        # 9. Recommendations
        lines.append("---")
        lines.append("")
        lines.append("## 9. Recommendations")
        lines.append("")
        if data["recommendations"]:
            for rec in data["recommendations"]:
                tech_id = rec.get("technique_id", "General")
                priority = rec.get("priority", "N/A")
                lines.append(f"### Priority {priority} — {tech_id}")
                lines.append("")
                actions = rec.get("actions", {})
                for action_type, action_list in actions.items():
                    lines.append(f"**{action_type.replace('_', ' ').title()}:**")
                    for action in action_list:
                        lines.append(f"- {action}")
                    lines.append("")
        else:
            lines.append("No specific recommendations at this time.")
            lines.append("")

        # 10. Conclusion
        lines.append("---")
        lines.append("")
        lines.append("## 10. Conclusion")
        lines.append("")
        lines.append(_strip_html(data["conclusion"]))
        lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append("*Report generated automatically by the Digital Forensics AI Platform — "
                     "MITRE ATT&CK Mapping Engine v1.0*")
        lines.append(f"*Generated on: {data['generation_timestamp']}*")

        content = "\n".join(lines)
        path = os.path.join(self.output_dir, "case_report.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        return path

    # ═══════════════════════════════════════════════════════════════════════════
    #  HTML REPORT
    # ═══════════════════════════════════════════════════════════════════════════

    def _generate_html(self, data: dict) -> str:
        """Generate the HTML report file using the template."""
        template_path = os.path.join(self.templates_dir, "report_template.html")

        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template = f.read()
        except FileNotFoundError:
            print(f"[WARN] HTML template not found: {template_path}. Generating inline.", file=sys.stderr)
            template = self._fallback_html_template()

        # Replace placeholders
        replacements = {
            "{{case_id}}":          html.escape(str(data["case_id"])),
            "{{category}}":         html.escape(data["category"].title()),
            "{{tool}}":             html.escape(str(data["tool"])),
            "{{analysis_date}}":    html.escape(data["analysis_date"]),
            "{{processing_time}}":  html.escape(str(data["processing_time"])),
            "{{generation_timestamp}}": html.escape(data["generation_timestamp"]),
            "{{executive_summary}}": data["executive_summary"],
            "{{conclusion}}":        data["conclusion"],
        }

        # AI Assessment metrics
        pred_class = "malicious" if data["prediction"] in ("MALICIOUS", "anomalous") else "safe"
        risk_class = data["risk_level"].lower() if data["risk_level"] else "safe"
        metrics_html = self._build_metrics_html(data, pred_class, risk_class)
        replacements["{{ai_assessment_metrics}}"] = metrics_html

        # Evidence summary
        evidence_html = self._build_evidence_html(data["evidence_items"])
        replacements["{{evidence_summary}}"] = evidence_html

        # Feature highlights
        features_html = self._build_features_table_html(data["feature_highlights"])
        replacements["{{feature_highlights_rows}}"] = features_html

        # MITRE techniques
        mitre_html = self._build_mitre_cards_html(data["techniques"])
        replacements["{{mitre_technique_cards}}"] = mitre_html

        # IOCs
        ioc_html = self._build_ioc_html(data["iocs"])
        replacements["{{ioc_items}}"] = ioc_html

        # Timeline
        timeline_html = self._build_timeline_html(data["timeline"])
        replacements["{{timeline_entries}}"] = timeline_html

        # Recommendations
        rec_html = self._build_recommendations_html(data["recommendations"])
        replacements["{{recommendations_html}}"] = rec_html

        # Apply replacements
        output = template
        for placeholder, value in replacements.items():
            output = output.replace(placeholder, str(value))

        path = os.path.join(self.output_dir, "case_report.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(output)

        return path

    # ─── HTML Section Builders ────────────────────────────────────────────────

    def _build_metrics_html(self, data: dict, pred_class: str, risk_class: str) -> str:
        """Build the AI assessment metric cards."""
        conf_pct = f"{data['confidence']:.0%}" if data['confidence'] else "N/A"
        return f"""
            <div class="metric-card">
                <div class="metric-label">Prediction</div>
                <div class="metric-value {pred_class}">{html.escape(data['prediction'])}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Risk Level</div>
                <div class="metric-value {risk_class}">{html.escape(data['risk_level'])}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Anomaly Score</div>
                <div class="metric-value {risk_class}">{data['anomaly_score']:.4f}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Confidence</div>
                <div class="metric-value">{conf_pct}</div>
            </div>
        """

    def _build_evidence_html(self, items: list) -> str:
        """Build evidence summary items."""
        parts = []
        for item in items:
            level = item.get("level", "medium")
            parts.append(f"""
                <div class="evidence-item {level}">
                    <div class="evidence-rank">#{item['rank']} — {html.escape(item.get('level', '').upper())}</div>
                    <div class="evidence-text">{html.escape(item['title'])}</div>
                    <div class="evidence-detail">{html.escape(item['detail'])}</div>
                </div>
            """)
        return "\n".join(parts) if parts else "<p>No evidence items.</p>"

    def _build_features_table_html(self, highlights: list) -> str:
        """Build feature highlight table rows."""
        rows = []
        for i, fh in enumerate(highlights, 1):
            sig_class = fh["significance"].lower()
            rows.append(f"""
                <tr>
                    <td>{i}</td>
                    <td>{html.escape(fh['label'])}</td>
                    <td><strong>{fh['value']}</strong></td>
                    <td><span class="badge badge-{sig_class}">{fh['significance']}</span> ({fh['ratio']}x threshold)</td>
                </tr>
            """)
        return "\n".join(rows) if rows else "<tr><td colspan='4'>No features exceeded thresholds.</td></tr>"

    def _build_mitre_cards_html(self, techniques: list) -> str:
        """Build MITRE technique cards."""
        if not techniques:
            return "<p>No MITRE ATT&CK techniques matched.</p>"

        cards = []
        for tech in techniques:
            severity = tech.get("severity", "Medium").lower()
            confidence = tech.get("confidence", 0)
            conf_pct = confidence * 100

            # Color for confidence bar
            if confidence >= 0.8:
                bar_color = "var(--accent-red)"
            elif confidence >= 0.6:
                bar_color = "var(--accent-orange)"
            elif confidence >= 0.4:
                bar_color = "var(--accent-yellow)"
            else:
                bar_color = "var(--accent-green)"

            cards.append(f"""
                <div class="technique-card">
                    <div class="technique-header">
                        <div>
                            <div class="technique-name">{html.escape(tech.get('name', 'Unknown'))}</div>
                            <div class="technique-tactic">{html.escape(tech.get('tactic', 'Unknown'))}</div>
                        </div>
                        <div style="text-align: right;">
                            <div class="technique-id">{html.escape(tech.get('id', 'N/A'))}</div>
                            <span class="badge badge-{severity}">{tech.get('severity', 'N/A')}</span>
                        </div>
                    </div>
                    <div style="color: var(--text-secondary); font-size: 13px; margin-bottom: 8px;">
                        {html.escape(tech.get('description', tech.get('recommendation', '')))}
                    </div>
                    <div style="display: flex; justify-content: space-between; font-size: 12px; color: var(--text-muted);">
                        <span>Confidence</span>
                        <span>{confidence:.0%}</span>
                    </div>
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: {conf_pct}%; background: {bar_color};"></div>
                    </div>
                </div>
            """)

        return "\n".join(cards)

    def _build_ioc_html(self, iocs: list) -> str:
        """Build IOC list HTML."""
        if not iocs:
            return "<p>No indicators of compromise identified.</p>"

        items = []
        for ioc in iocs:
            items.append(f"""
                <div class="ioc-item">
                    <span class="ioc-type">{html.escape(ioc['type'])}</span>
                    <span class="ioc-value">{html.escape(str(ioc['value']))}</span>
                </div>
            """)
        return "\n".join(items)

    def _build_timeline_html(self, timeline: list) -> str:
        """Build timeline entries HTML."""
        if not timeline:
            return "<p>No timeline data available.</p>"

        entries = []
        for entry in timeline:
            entries.append(f"""
                <div class="timeline-entry">
                    <div class="timeline-time">{html.escape(str(entry['timestamp']))}</div>
                    <div class="timeline-desc">{html.escape(entry['event'])}</div>
                </div>
            """)
        return "\n".join(entries)

    def _build_recommendations_html(self, recommendations: list) -> str:
        """Build recommendations HTML."""
        if not recommendations:
            return "<p>No specific recommendations at this time.</p>"

        parts = []
        for rec in recommendations:
            tech_id  = rec.get("technique_id", "General")
            priority = rec.get("priority", "N/A")
            actions  = rec.get("actions", {})

            parts.append(f"""
                <div style="margin-bottom: 24px; padding: 16px; background: var(--bg-secondary); border-radius: 10px;">
                    <div style="font-weight: 600; margin-bottom: 12px; color: var(--accent-cyan);">
                        Priority {priority} — {html.escape(tech_id)}
                    </div>
            """)

            for action_type, action_list in actions.items():
                title = action_type.replace("_", " ").title()
                parts.append(f"""
                    <div class="rec-category">
                        <div class="rec-category-title">{html.escape(title)}</div>
                """)
                for action in action_list:
                    parts.append(f"""
                        <div class="rec-item">
                            <span class="rec-bullet">▸</span>
                            <span>{html.escape(action)}</span>
                        </div>
                    """)
                parts.append("</div>")

            parts.append("</div>")

        return "\n".join(parts)

    def _fallback_html_template(self) -> str:
        """Minimal fallback HTML if template file is missing."""
        return """<!DOCTYPE html>
<html><head><title>Forensic Report — {{case_id}}</title>
<style>body{font-family:sans-serif;margin:40px;background:#111;color:#eee;}
table{border-collapse:collapse;width:100%;}th,td{border:1px solid #333;padding:8px;text-align:left;}
th{background:#222;}</style></head>
<body>
<h1>Digital Forensics Report — {{case_id}}</h1>
<p>{{executive_summary}}</p>
{{ai_assessment_metrics}}
{{evidence_summary}}
{{feature_highlights_rows}}
{{mitre_technique_cards}}
{{ioc_items}}
{{timeline_entries}}
{{recommendations_html}}
{{conclusion}}
<hr><p>Generated: {{generation_timestamp}}</p>
</body></html>"""


# ═══════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def _strip_html(text: str) -> str:
    """Remove HTML tags for plain text / markdown output."""
    text = re.sub(r"<strong>(.*?)</strong>", r"**\1**", text)
    text = re.sub(r"<p>(.*?)</p>", r"\1\n", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import argparse

    ap = argparse.ArgumentParser(
        description="Digital Forensics Report Generator"
    )
    ap.add_argument(
        "--mapping", "-m", required=True,
        help="Path to mitre_mapping.json (output of mapper.py)"
    )
    ap.add_argument(
        "--prediction", "-p", default=None,
        help="Path to prediction JSON from the AI pipeline (optional, enriches report)"
    )
    ap.add_argument(
        "--features", "-f", default=None,
        help="Path to feature vector JSON (if separate from prediction)"
    )
    ap.add_argument(
        "--evidence", "-e", default=None,
        help="Path to parsed evidence JSON (optional)"
    )
    ap.add_argument(
        "--output", "-o", default=REPORTS_DIR,
        help="Output directory for reports (default: core/reporting/reports/)"
    )
    ap.add_argument(
        "--case-id", default=None,
        help="Override case ID"
    )
    args = ap.parse_args()

    # Load MITRE mapping
    print("=" * 60)
    print("  Digital Forensics Report Generator")
    print("=" * 60)
    print(f"  Mapping  : {args.mapping}")
    print(f"  Output   : {args.output}")
    print()

    with open(args.mapping, "r", encoding="utf-8") as f:
        mitre_mapping = json.load(f)
    print(f"[INFO] Loaded MITRE mapping: {args.mapping}")

    # Load optional inputs
    prediction_data = None
    if args.prediction:
        with open(args.prediction, "r", encoding="utf-8") as f:
            prediction_data = json.load(f)
        print(f"[INFO] Loaded prediction: {args.prediction}")

    feature_vector = None
    if args.features:
        with open(args.features, "r", encoding="utf-8") as f:
            feature_vector = json.load(f)
        print(f"[INFO] Loaded features: {args.features}")

    parsed_evidence = None
    if args.evidence:
        with open(args.evidence, "r", encoding="utf-8") as f:
            parsed_evidence = json.load(f)
        print(f"[INFO] Loaded evidence: {args.evidence}")

    print()

    # Generate reports
    generator = ForensicReportGenerator(output_dir=args.output)
    paths = generator.generate(
        mitre_mapping=mitre_mapping,
        prediction_data=prediction_data,
        feature_vector=feature_vector,
        parsed_evidence=parsed_evidence,
        case_id=args.case_id,
    )

    print("[INFO] Reports generated:")
    for fmt, path in paths.items():
        print(f"  [{fmt.upper():>4}] {path}")
    print()
    print("Done.")


if __name__ == "__main__":
    main()
