"""
browser_report_generator.py — Digital Forensics Report Generator (Browser category)
====================================================================================
A separate report generator for the browser category, since predict_browser_case()
returns a PER-URL list (each URL has its own prediction/confidence/risk_level)
rather than a single case-level flat feature_vector like malware/network.
Uses browser_report_template.html — URL table instead of feature-highlights table.

Input:
    - browser_prediction: the dict returned by inference.predict.predict_browser_case()
    - mitre_mapping: optional (browser MITRE rules are not built yet — pass None
      until ai_engine/mitre/rules/browser_rules.json + a browser mitre_runner.py exist)

Output:
    - case_report.md
    - case_report.html
    - case_report.json

Usage:
    from browser_report_generator import BrowserReportGenerator
    gen = BrowserReportGenerator(output_dir="reports")
    gen.generate(browser_prediction=predict_browser_case_output)
"""

import json
import os
import sys
import html
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(SCRIPT_DIR, "templates")
REPORTS_DIR   = os.path.join(SCRIPT_DIR, "reports")


class BrowserReportGenerator:
    """Generates Markdown, HTML, and JSON reports for the browser (phishing URL) category."""

    def __init__(self, output_dir: str = None, templates_dir: str = None):
        self.output_dir    = output_dir or REPORTS_DIR
        self.templates_dir = templates_dir or TEMPLATES_DIR
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(
        self,
        browser_prediction: dict,
        mitre_mapping: dict = None,
        case_id: str = None,
    ) -> Dict[str, str]:
        report_data = self._prepare_report_data(browser_prediction, mitre_mapping, case_id)
        paths = {}
        paths["json"] = self._generate_json(report_data)
        paths["md"]   = self._generate_markdown(report_data)
        paths["html"] = self._generate_html(report_data)
        return paths

    # ─── Data Preparation ─────────────────────────────────────────────────────

    def _prepare_report_data(self, pred: dict, mitre_mapping: dict, case_id: str) -> dict:
        now = datetime.now(timezone.utc)
        summary = pred.get("summary", {})
        predictions = pred.get("predictions", [])
        high_risk = pred.get("high_risk_urls", [])
        cid = case_id or pred.get("case_id", f"CASE-{now.strftime('%Y%m%d-%H%M%S')}")

        total = summary.get("total_urls", 0)
        phishing_count = summary.get("phishing_count", 0)
        high_risk_count = summary.get("high_risk_count", 0)
        login_phishing_count = summary.get("login_phishing_count", 0)
        phishing_rate = summary.get("phishing_rate", 0)

        overall_prediction = "MALICIOUS" if phishing_count > 0 else "SAFE"
        overall_risk_level = (
            "CRITICAL" if login_phishing_count > 0 else
            "HIGH" if high_risk_count > 0 else
            "MEDIUM" if phishing_count > 0 else
            "SAFE"
        )

        techniques = mitre_mapping.get("techniques", []) if mitre_mapping else []
        recommendations = mitre_mapping.get("recommendations", []) if mitre_mapping else []

        iocs = self._extract_iocs(predictions)
        exec_summary = self._build_executive_summary(total, phishing_count, high_risk_count, login_phishing_count, phishing_rate)
        conclusion = self._build_conclusion(overall_prediction, overall_risk_level, phishing_count, login_phishing_count)

        return {
            "case_id": cid,
            "source_file": pred.get("source_file", "N/A"),
            "analysis_date": now.isoformat(),
            "prediction": overall_prediction,
            "risk_level": overall_risk_level,
            "total_urls": total,
            "phishing_count": phishing_count,
            "high_risk_count": high_risk_count,
            "login_phishing_count": login_phishing_count,
            "phishing_rate": phishing_rate,
            "executive_summary": exec_summary,
            "predictions": predictions,
            "high_risk_urls": high_risk,
            "techniques": techniques,
            "iocs": iocs,
            "recommendations": recommendations,
            "conclusion": conclusion,
            "generation_timestamp": now.isoformat(),
        }

    def _extract_iocs(self, predictions: list) -> List[Dict[str, str]]:
        iocs = []
        for p in predictions:
            if p.get("prediction") == "phishing" and p.get("is_login_url"):
                iocs.append({"type": "Credential Exposure", "feature": "login_url", "value": p["url"], "detail": f"Password saved on suspected phishing URL: {p['url']}"})
            if p.get("prediction") == "phishing" and p.get("is_download_url"):
                iocs.append({"type": "Malicious Download", "feature": "download_url", "value": p["url"], "detail": f"File downloaded from suspected phishing URL: {p['url']}"})
        return iocs

    def _build_executive_summary(self, total, phishing_count, high_risk_count, login_phishing_count, phishing_rate) -> str:
        if phishing_count == 0:
            return (f"The Browser Forensics AI pipeline analyzed <strong>{total}</strong> URLs from browser "
                    f"history and found <strong>no phishing indicators</strong>. All URLs fall within normal "
                    f"browsing patterns.")
        summary = (f"The Browser Forensics AI pipeline analyzed <strong>{total}</strong> URLs and identified "
                   f"<strong>{phishing_count}</strong> as phishing (<strong>{phishing_rate}%</strong> of total), "
                   f"with <strong>{high_risk_count}</strong> classified as HIGH risk.")
        if login_phishing_count > 0:
            summary += (f" Critically, <strong>{login_phishing_count}</strong> phishing URL(s) had saved "
                        f"credentials, indicating potential credential compromise requiring immediate action.")
        return summary

    def _build_conclusion(self, prediction, risk_level, phishing_count, login_phishing_count) -> str:
        if phishing_count == 0:
            return ("<p>Based on the automated analysis of browser history evidence, no phishing URLs were "
                    "detected. Browsing activity appears to represent normal operational patterns. "
                    "No immediate action is required, but routine monitoring should continue.</p>")
        base = (f"<p>Based on the automated analysis of browser history evidence, <strong>{phishing_count}</strong> "
                f"phishing URL(s) were identified, indicating the user's system has been exposed to "
                f"credential-harvesting or malicious download attempts.</p>")
        if login_phishing_count > 0:
            base += ("<p>Because credentials were saved on one or more phishing pages, treat this as a "
                     "<strong>confirmed credential compromise</strong>: force a password reset for any accounts "
                     "used on those pages, enable multi-factor authentication, and review account activity for "
                     "unauthorized access. All volatile evidence (browser cache, saved-password store) should be "
                     "preserved before remediation.</p>")
        else:
            base += (f"<p>The risk assessment is <strong>{risk_level}</strong>. A manual review of the flagged "
                     f"URLs is recommended, along with user awareness follow-up.</p>")
        return base

    # ─── JSON ─────────────────────────────────────────────────────────────────

    def _generate_json(self, data: dict) -> str:
        report = {
            "report_version": "1.0.0",
            "case_information": {
                "case_id": data["case_id"], "category": "browser",
                "source_file": data["source_file"], "analysis_date": data["analysis_date"],
            },
            "ai_assessment": {
                "prediction": data["prediction"], "risk_level": data["risk_level"],
                "total_urls": data["total_urls"], "phishing_count": data["phishing_count"],
                "high_risk_count": data["high_risk_count"],
                "login_phishing_count": data["login_phishing_count"],
                "phishing_rate": data["phishing_rate"],
            },
            "url_predictions": data["predictions"],
            "high_risk_urls": data["high_risk_urls"],
            "mitre_mapping": {
                "techniques_matched": len(data["techniques"]), "techniques": data["techniques"],
                "note": None if data["techniques"] else "Browser MITRE mapping not yet implemented.",
            },
            "indicators_of_compromise": data["iocs"],
            "recommendations": data["recommendations"],
            "conclusion": _strip_html(data["conclusion"]),
            "generation_timestamp": data["generation_timestamp"],
        }
        path = os.path.join(self.output_dir, "case_report.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        return path

    # ─── Markdown ─────────────────────────────────────────────────────────────

    def _generate_markdown(self, data: dict) -> str:
        lines = []
        lines.append(f"# Browser Forensics Report — {data['case_id']}")
        lines.append(""); lines.append("---"); lines.append("")
        lines.append("## 1. Case Information"); lines.append("")
        lines.append("| Field | Value |"); lines.append("|-------|-------|")
        lines.append(f"| **Case ID** | {data['case_id']} |")
        lines.append(f"| **Source File** | {data['source_file']} |")
        lines.append(f"| **Analysis Date** | {data['analysis_date']} |"); lines.append("")
        lines.append("---"); lines.append(""); lines.append("## 2. Executive Summary"); lines.append("")
        lines.append(_strip_html(data["executive_summary"])); lines.append("")
        lines.append("---"); lines.append(""); lines.append("## 3. AI Assessment"); lines.append("")
        lines.append("| Metric | Value |"); lines.append("|--------|-------|")
        lines.append(f"| **Prediction** | {data['prediction']} |")
        lines.append(f"| **Risk Level** | {data['risk_level']} |")
        lines.append(f"| **Total URLs** | {data['total_urls']} |")
        lines.append(f"| **Phishing Count** | {data['phishing_count']} |")
        lines.append(f"| **High Risk Count** | {data['high_risk_count']} |")
        lines.append(f"| **Login+Phishing Count** | {data['login_phishing_count']} |")
        lines.append(f"| **Phishing Rate** | {data['phishing_rate']}% |"); lines.append("")
        lines.append("---"); lines.append(""); lines.append("## 4. High-Risk URLs"); lines.append("")
        if data["high_risk_urls"]:
            lines.append("| URL | Prediction | Confidence | Reason |")
            lines.append("|-----|------------|------------|--------|")
            for u in data["high_risk_urls"]:
                lines.append(f"| {u['url']} | {u['prediction']} | {u['confidence']:.0%} | {u['reason']} |")
            lines.append("")
        else:
            lines.append("No high-risk URLs identified."); lines.append("")
        lines.append("---"); lines.append(""); lines.append("## 5. Full URL Analysis"); lines.append("")
        lines.append("| URL | Prediction | Confidence | Risk | Login | Download |")
        lines.append("|-----|------------|------------|------|-------|----------|")
        for p in data["predictions"]:
            lines.append(f"| {p['url']} | {p['prediction']} | {p['confidence']:.0%} | {p['risk_level']} | "
                          f"{'Yes' if p.get('is_login_url') else 'No'} | {'Yes' if p.get('is_download_url') else 'No'} |")
        lines.append("")
        lines.append("---"); lines.append(""); lines.append("## 6. MITRE ATT&CK Mapping"); lines.append("")
        if data["techniques"]:
            lines.append("| # | ID | Technique | Tactic | Confidence | Severity |")
            lines.append("|---|-----|-----------|--------|------------|----------|")
            for i, tech in enumerate(data["techniques"], 1):
                lines.append(f"| {i} | {tech.get('id', 'N/A')} | {tech.get('name', 'N/A')} | "
                              f"{tech.get('tactic', 'N/A')} | {tech.get('confidence', 0):.0%} | {tech.get('severity', 'N/A')} |")
            lines.append("")
        else:
            lines.append("_Browser MITRE mapping not yet implemented — no techniques to display._"); lines.append("")
        lines.append("---"); lines.append(""); lines.append("## 7. Indicators of Compromise"); lines.append("")
        if data["iocs"]:
            lines.append("| Type | Value |"); lines.append("|------|-------|")
            for ioc in data["iocs"]:
                lines.append(f"| {ioc['type']} | {ioc['value']} |")
            lines.append("")
        else:
            lines.append("No indicators of compromise identified."); lines.append("")
        lines.append("---"); lines.append(""); lines.append("## 8. Recommendations"); lines.append("")
        if data["recommendations"]:
            for rec in data["recommendations"]:
                lines.append(f"- {rec}")
            lines.append("")
        else:
            if data["login_phishing_count"] > 0:
                lines.append("- Force password reset for accounts used on flagged login pages")
                lines.append("- Enable multi-factor authentication where available")
                lines.append("- Review account activity logs for unauthorized access")
            elif data["phishing_count"] > 0:
                lines.append("- Manually review flagged URLs")
                lines.append("- Provide user awareness follow-up on phishing recognition")
            else:
                lines.append("- No action required; continue routine monitoring")
            lines.append("")
        lines.append("---"); lines.append(""); lines.append("## 9. Conclusion"); lines.append("")
        lines.append(_strip_html(data["conclusion"])); lines.append("")
        lines.append("---"); lines.append("")
        lines.append("*Report generated automatically by the Digital Forensics AI Platform — Browser Phishing Detection Engine v1.0*")
        lines.append(f"*Generated on: {data['generation_timestamp']}*")

        content = "\n".join(lines)
        path = os.path.join(self.output_dir, "case_report.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    # ─── HTML ─────────────────────────────────────────────────────────────────

    def _generate_html(self, data: dict) -> str:
        template_path = os.path.join(self.templates_dir, "browser_report_template.html")
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template = f.read()
        except FileNotFoundError:
            print(f"[WARN] Template not found: {template_path}", file=sys.stderr)
            template = "<html><body><h1>{{case_id}}</h1>{{executive_summary}}</body></html>"

        pred_class = "malicious" if data["prediction"] == "MALICIOUS" else "safe"
        risk_class = data["risk_level"].lower()

        replacements = {
            "{{case_id}}": html.escape(str(data["case_id"])),
            "{{source_file}}": html.escape(str(data["source_file"])),
            "{{analysis_date}}": html.escape(data["analysis_date"]),
            "{{generation_timestamp}}": html.escape(data["generation_timestamp"]),
            "{{executive_summary}}": data["executive_summary"],
            "{{conclusion}}": data["conclusion"],
            "{{ai_assessment_metrics}}": self._build_metrics_html(data, pred_class, risk_class),
            "{{high_risk_urls_table}}": self._build_high_risk_table_html(data["high_risk_urls"]),
            "{{url_table_rows}}": self._build_url_rows_html(data["predictions"]),
            "{{mitre_technique_cards}}": self._build_mitre_cards_html(data["techniques"]),
            "{{ioc_items}}": self._build_ioc_html(data["iocs"]),
            "{{recommendations_html}}": self._build_recommendations_html(data),
        }

        output = template
        for placeholder, value in replacements.items():
            output = output.replace(placeholder, str(value))

        path = os.path.join(self.output_dir, "case_report.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(output)
        return path

    def _build_metrics_html(self, data, pred_class, risk_class) -> str:
        return f"""
            <div class="metric-card"><div class="metric-label">Prediction</div><div class="metric-value {pred_class}">{html.escape(data['prediction'])}</div></div>
            <div class="metric-card"><div class="metric-label">Risk Level</div><div class="metric-value {risk_class}">{html.escape(data['risk_level'])}</div></div>
            <div class="metric-card"><div class="metric-label">Total URLs</div><div class="metric-value">{data['total_urls']}</div></div>
            <div class="metric-card"><div class="metric-label">Phishing Found</div><div class="metric-value {'critical' if data['phishing_count'] else 'safe'}">{data['phishing_count']}</div></div>
            <div class="metric-card"><div class="metric-label">Phishing Rate</div><div class="metric-value">{data['phishing_rate']}%</div></div>
        """

    def _build_high_risk_table_html(self, high_risk: list) -> str:
        if not high_risk:
            return "<p>No high-risk URLs identified.</p>"
        rows = []
        for u in high_risk:
            rows.append(f"""
                <tr>
                    <td>{html.escape(u['url'])}</td>
                    <td><span class="badge badge-{'phishing' if u['prediction']=='phishing' else 'benign'}">{u['prediction']}</span></td>
                    <td>{u['confidence']:.0%}</td>
                    <td>{'🔑' if u.get('is_login_url') else ''} {'⬇️' if u.get('is_download_url') else ''}</td>
                    <td>{html.escape(u.get('reason',''))}</td>
                </tr>
            """)
        return f"""<table><thead><tr><th>URL</th><th>Prediction</th><th>Confidence</th><th>Flags</th><th>Reason</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"""

    def _build_url_rows_html(self, predictions: list) -> str:
        rows = []
        for p in predictions:
            risk = p.get("risk_level", "LOW").lower()
            rows.append(f"""
                <tr>
                    <td>{html.escape(p['url'])}</td>
                    <td><span class="badge badge-{'phishing' if p['prediction']=='phishing' else 'benign'}">{p['prediction']}</span></td>
                    <td>{p['confidence']:.0%}</td>
                    <td><span class="badge badge-{risk}">{p.get('risk_level','N/A')}</span></td>
                    <td>{p.get('layer','N/A')}</td>
                    <td class="flag-icon">{'🔑' if p.get('is_login_url') else '—'}</td>
                    <td class="flag-icon">{'⬇️' if p.get('is_download_url') else '—'}</td>
                    <td>{p.get('visit_count', 0)}</td>
                </tr>
            """)
        return "\n".join(rows) if rows else "<tr><td colspan='8'>No URLs found.</td></tr>"

    def _build_mitre_cards_html(self, techniques: list) -> str:
        if not techniques:
            return '<p class="placeholder-note">Browser MITRE ATT&CK mapping is not yet implemented for this category — no rules.json/mapper runner exists yet.</p>'
        cards = []
        for tech in techniques:
            severity = tech.get("severity", "Medium").lower()
            confidence = tech.get("confidence", 0)
            cards.append(f"""
                <div style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 10px; padding: 16px; margin-bottom: 12px;">
                    <strong>{html.escape(tech.get('id','N/A'))} — {html.escape(tech.get('name','Unknown'))}</strong>
                    <span class="badge badge-{severity}" style="float:right;">{tech.get('severity','N/A')}</span>
                    <div style="color: var(--text-secondary); font-size: 13px; margin-top: 8px;">
                        {html.escape(tech.get('tactic',''))} · Confidence {confidence:.0%}
                    </div>
                </div>
            """)
        return "\n".join(cards)

    def _build_ioc_html(self, iocs: list) -> str:
        if not iocs:
            return "<p>No indicators of compromise identified.</p>"
        items = []
        for ioc in iocs:
            items.append(f"""
                <div class="ioc-item" style="display:flex;align-items:center;gap:12px;padding:10px 16px;background:var(--bg-secondary);border-radius:8px;margin-bottom:8px;font-family:'Consolas',monospace;font-size:13px;">
                    <span class="ioc-type" style="font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--accent-purple);font-weight:600;min-width:140px;font-family:'Segoe UI',sans-serif;">{html.escape(ioc['type'])}</span>
                    <span style="color:var(--text-primary);word-break:break-all;">{html.escape(str(ioc['value']))}</span>
                </div>
            """)
        return "\n".join(items)

    def _build_recommendations_html(self, data: dict) -> str:
        recs = data["recommendations"]
        if recs:
            items = "".join(f'<div class="rec-item" style="padding:6px 0;">▸ {html.escape(str(r))}</div>' for r in recs)
            return items
        if data["login_phishing_count"] > 0:
            defaults = [
                "Force password reset for accounts used on flagged login pages",
                "Enable multi-factor authentication where available",
                "Review account activity logs for unauthorized access",
                "Preserve browser cache and saved-password store as evidence before remediation",
            ]
        elif data["phishing_count"] > 0:
            defaults = ["Manually review flagged URLs", "Provide user awareness follow-up on phishing recognition"]
        else:
            defaults = ["No action required; continue routine monitoring"]
        return "".join(f'<div class="rec-item" style="padding:6px 0;">▸ {html.escape(d)}</div>' for d in defaults)


def _strip_html(text: str) -> str:
    text = re.sub(r"<strong>(.*?)</strong>", r"**\1**", text)
    text = re.sub(r"<p>(.*?)</p>", r"\1\n", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Browser Forensics Report Generator")
    ap.add_argument("--prediction", "-p", required=True, help="Path to predict_browser_case() output JSON")
    ap.add_argument("--mapping", "-m", default=None, help="Optional path to a browser MITRE mapping JSON (not built yet)")
    ap.add_argument("--output", "-o", default=REPORTS_DIR)
    ap.add_argument("--case-id", default=None)
    args = ap.parse_args()

    with open(args.prediction, "r", encoding="utf-8") as f:
        browser_prediction = json.load(f)

    mitre_mapping = None
    if args.mapping:
        with open(args.mapping, "r", encoding="utf-8") as f:
            mitre_mapping = json.load(f)

    generator = BrowserReportGenerator(output_dir=args.output)
    paths = generator.generate(browser_prediction=browser_prediction, mitre_mapping=mitre_mapping, case_id=args.case_id)

    print("[INFO] Reports generated:")
    for fmt, path in paths.items():
        print(f"  [{fmt.upper():>4}] {path}")


if __name__ == "__main__":
    main()
