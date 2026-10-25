"""
Wave 5: Executive & Technical Reporting Specialist Agent.
Aggregates quality-gated findings, computes CVSS risk posture metrics,
and exports interactive HTML, Markdown, and machine-readable JSON reports.
"""

import json
import re
import html
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from core.schemas import (
    AssessmentReport,
    VAPTSummary,
    TargetScope,
    ReconData,
    QualityGateResult,
    VulnerabilityFinding,
    SeverityLevel
)


class ReporterAgent:
    """Specialist agent that synthesizes final VAPT audit dossiers."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        scope: TargetScope,
        recon: ReconData,
        quality_gates: List[QualityGateResult],
        findings: List[VulnerabilityFinding],
        threat_model: Optional[Any] = None
    ) -> AssessmentReport:
        # Calculate summary statistics
        crit = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        med = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
        low = sum(1 for f in findings if f.severity == SeverityLevel.LOW)
        info = sum(1 for f in findings if f.severity == SeverityLevel.INFORMATIONAL)

        mean_cvss = round(sum(f.cvss.base_score for f in findings) / len(findings), 1) if findings else 0.0

        # Calculate coverage rate from testing quality gate
        coverage_rate = 100.0
        for qg in quality_gates:
            if "Wave 4" in qg.wave_name:
                coverage_rate = qg.coverage_score

        summary = VAPTSummary(
            total_findings=len(findings),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            info_count=info,
            mean_cvss=mean_cvss,
            coverage_rate=coverage_rate
        )

        # Build executive overview
        if crit > 0 or high > 0:
            posture = "ELEVATED RISK"
            narrative = f"The automated assessment identified {crit} Critical and {high} High-severity vulnerability vectors. Immediate remediation is mandatory prior to production release."
        elif med > 0:
            posture = "MODERATE RISK"
            narrative = f"The assessment revealed {med} Medium-severity flaws. Remediation should be scheduled within standard sprint cycles."
        else:
            posture = "SECURE / LOW RISK"
            narrative = "No critical or high-risk exploit vectors were discovered. Basic defense-in-depth hygiene should be maintained."

        exec_overview = (
            f"Target System: {scope.target_url}\n"
            f"Overall Posture: {posture}\n"
            f"Mean CVSS Base Score: {mean_cvss}/10.0\n"
            f"Attack Surface Test Coverage: {coverage_rate}%\n"
            f"{narrative}"
        )

        # Build prioritized remediation plan
        remediation_plan = []
        # Sort findings by CVSS base score descending
        sorted_findings = sorted(findings, key=lambda x: x.cvss.base_score, reverse=True)
        for idx, f in enumerate(sorted_findings, 1):
            remediation_plan.append({
                "priority": idx,
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity.value,
                "cvss_score": f.cvss.base_score,
                "affected_url": f.affected_url,
                "remediation_action": f.remediation_advice
            })

        parsed = urlparse(scope.target_url)
        raw_name = (parsed.netloc or parsed.path).replace(":", "_")
        safe_target = re.sub(r"[^a-zA-Z0-9_]", "_", raw_name).strip("_").lower() or "target"
        now_utc = datetime.now(timezone.utc)
        timestamp_str = now_utc.strftime("%Y%m%d_%H%M%S")
        file_prefix = f"vapt_report_{safe_target}_{timestamp_str}"
        report_id = f"VAPT-REPORT-{safe_target.upper()}-{timestamp_str}"

        report = AssessmentReport(
            report_id=report_id,
            generated_at=now_utc,
            target=scope,
            summary=summary,
            executive_overview=exec_overview,
            reconnaissance=recon,
            quality_gates=quality_gates,
            threat_model=threat_model.model_dump() if hasattr(threat_model, 'model_dump') else threat_model,
            findings=sorted_findings,
            remediation_plan=remediation_plan
        )

        # Export formats with target domain in filename
        self._export_json(report, file_prefix)
        self._export_markdown(report, file_prefix)
        self._export_html(report, file_prefix)

        return report

    def _export_json(self, report: AssessmentReport, file_prefix: str):
        path = self.output_dir / f"{file_prefix}.json"
        with open(path, "w", encoding="utf-8") as f:
            f.write(report.model_dump_json(indent=2))

    def _export_markdown(self, report: AssessmentReport, file_prefix: str):
        path = self.output_dir / f"{file_prefix}.md"
        lines = [
            f"# 🛡️ AI Penetration Testing Assessment Report",
            f"**Report ID**: `{report.report_id}`  ",
            f"**Target**: `{report.target.target_url}`  ",
            f"**Generated**: `{report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}`  ",
            f"**Engineered by**: `Harshit Nigam`  ",
            f"**Attack Surface Coverage**: `{report.summary.coverage_rate}%`  ",
            "",
            "## 📊 Executive Summary",
            f"- **Total Findings**: {report.summary.total_findings}",
            f"- **Critical**: {report.summary.critical_count} | **High**: {report.summary.high_count} | **Medium**: {report.summary.medium_count} | **Low**: {report.summary.low_count}",
            f"- **Average CVSS Score**: {report.summary.mean_cvss} / 10.0",
            "",
            f"```text\n{report.executive_overview}\n```",
            "",
            "## 🚪 Quality Gate Status Across Wave Pipeline",
        ]

        for qg in report.quality_gates:
            status_icon = "✅" if qg.status.value == "PASSED" else "⚠️"
            lines.append(f"### {status_icon} {qg.wave_name} ({qg.status.value})")
            lines.append(f"- Coverage Score: `{qg.coverage_score}%`")
            lines.append(f"- Surfaces Audited: `{qg.attack_surfaces_tested} / {qg.total_attack_surfaces}`")
            lines.append(f"- Findings Verified / Submitted: `{qg.findings_verified} / {qg.findings_submitted}`")
            if qg.quality_notes:
                for note in qg.quality_notes:
                    lines.append(f"  - {note}")
            lines.append("")

        if report.threat_model and isinstance(report.threat_model, dict) and report.threat_model.get("threats"):
            lines.append("## 🏛️ Microsoft STRIDE Threat Modeling Architecture")
            lines.append(f"**Total Architectural Threats Mapped**: {report.threat_model.get('total_threats', 0)}\n")
            for t in report.threat_model.get("threats", []):
                lines.append(f"### [{t.get('risk_level', 'HIGH')}] {t.get('category')}: {t.get('title')} ({t.get('threat_id')})")
                lines.append(f"- **Description**: {t.get('description')}")
                lines.append(f"- **Affected Components**: `{', '.join(t.get('affected_components', []))}`")
                lines.append(f"- **Defensive Mitigation**: {t.get('mitigation_strategy')}")
                lines.append(f"- **OWASP Mapping**: `{t.get('owasp_mapping')}` | **CWE**: `{t.get('cwe_id')}`\n")
            lines.append("---\n")

        lines.append("## 🔍 Verified Vulnerability Findings")
        for f in report.findings:
            lines.append(f"### [{f.severity.value}] {f.title} ({f.finding_id})")
            lines.append("")
            lines.append("#### 💡 Plain English Breakdown (Non-Technical)")
            lines.append(f"> **Simple Explanation**: {f.plain_english_summary or f.description}")
            lines.append("")
            lines.append(f"- 📍 **Where is the Flaw?**: {f.where_is_the_flaw or f'{f.http_method} {f.affected_url}'}")
            lines.append(f"- 💥 **Real-World Impact**: {f.real_world_impact or 'Potential unauthorized access or compromise.'}")
            lines.append("")
            lines.append("#### 🏴‍☠️ How an Attacker Can Exploit This (Adversary Kill Chain)")
            if f.how_attacker_exploits:
                for step in f.how_attacker_exploits.split("\n"):
                    if step.strip():
                        lines.append(f"- {step.strip()}")
            else:
                lines.append("- Attacker identifies the exposed input and crafts malicious requests to bypass controls.")
            lines.append("")
            lines.append("#### 🔬 Technical Forensics")
            lines.append(f"- **CVSS v3.1**: `{f.cvss.base_score}` (`{f.cvss.vector_string}`)")
            lines.append(f"- **OWASP Category**: `{f.owasp_top10}` | **CWE**: `{f.cwe_id}`")
            lines.append(f"- **Endpoint**: `{f.http_method} {f.affected_url}`")
            lines.append(f"- **Parameter**: `{f.affected_parameter or 'None'}`")
            lines.append(f"- **Confidence**: `{f.confidence.value}` (Proof Fingerprint: `{f.evidence.proof_hash}`)")
            lines.append(f"- **Technical Description**: {f.description}")
            lines.append("")
            lines.append("#### 🧪 Reproducible Proof of Concept (cURL Command)")
            lines.append(f"```bash\n{f.evidence.curl_reproduction}\n```")
            lines.append("")
            lines.append("#### 🛠️ Remediation Guidance")
            lines.append(f"{f.remediation_advice}")
            if f.remediation_code_sample:
                lines.append(f"\n```python\n{f.remediation_code_sample}\n```")
            lines.append("\n---\n")

        with open(path, "w", encoding="utf-8") as out:
            out.write("\n".join(lines))

    def _export_html(self, report: AssessmentReport, file_prefix: str):
        path = self.output_dir / f"{file_prefix}.html"
        
        # Write .latest_html.txt for batch runners
        latest_pointer = self.output_dir / ".latest_html.txt"
        try:
            with open(latest_pointer, "w", encoding="utf-8") as lf:
                lf.write(f"reports/{file_prefix}.html")
        except Exception:
            pass

        findings_html = ""
        for f in report.findings:
            badge_color = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#3b82f6",
                "INFORMATIONAL": "#64748b"
            }.get(f.severity.value, "#64748b")

            code_sample_html = ""
            if f.remediation_code_sample:
                escaped_code = html.escape(f.remediation_code_sample)
                code_sample_html = f"<div class='code-block'><pre><code>{escaped_code}</code></pre></div>"

            # Format exploit steps cleanly
            exploit_steps_html = ""
            if f.how_attacker_exploits:
                steps = [s.strip() for s in f.how_attacker_exploits.split("\n") if s.strip()]
                for s in steps:
                    exploit_steps_html += f"<div class='exploit-step'><span class='step-icon'>⚡</span><span class='step-desc'>{html.escape(s)}</span></div>"
            else:
                exploit_steps_html = "<div class='exploit-step'><span class='step-icon'>⚡</span><span class='step-desc'>Attacker crafts requests targeting this endpoint to bypass security controls.</span></div>"

            plain_summary = html.escape(f.plain_english_summary or f.description)
            flaw_loc = html.escape(f.where_is_the_flaw or f"{f.http_method} {f.affected_url} (Parameter: {f.affected_parameter or 'None'})")
            impact_text = html.escape(f.real_world_impact or "Unauthorized access, data disclosure, or privilege escalation.")

            findings_html += f"""
            <div class="card finding-card severity-{f.severity.value.lower()}" data-severity="{f.severity.value}">
              <div class="card-header">
                <div class="header-left">
                  <span class="badge" style="background: {badge_color}; color: #fff;">{f.severity.value} {f.cvss.base_score}</span>
                  <span class="finding-id">{html.escape(f.finding_id)}</span>
                  <h3 class="finding-title">{html.escape(f.title)}</h3>
                </div>
                <span class="badge badge-outline">{html.escape(f.cwe_id)}</span>
              </div>

              <!-- PLAIN ENGLISH NON-TECHNICAL BREAKDOWN -->
              <div class="section-box plain-english-box">
                <div class="box-title">💡 Plain English Breakdown (Non-Technical Summary)</div>
                <p class="plain-summary-text">{plain_summary}</p>
                <div class="flaw-callout">
                  <div class="callout-item">
                    <span class="callout-lbl">📍 Where is the Flaw:</span>
                    <span class="callout-val flaw-highlight">{flaw_loc}</span>
                  </div>
                  <div class="callout-item" style="margin-top: 8px;">
                    <span class="callout-lbl">💥 Business & User Impact:</span>
                    <span class="callout-val impact-highlight">{impact_text}</span>
                  </div>
                </div>
              </div>

              <!-- HOW AN ATTACKER EXPLOITS THIS -->
              <div class="section-box exploit-box">
                <div class="box-title">🏴‍☠️ How an Attacker Can Exploit This (Attack Scenario)</div>
                <div class="exploit-chain">
                  {exploit_steps_html}
                </div>
              </div>

              <!-- TECHNICAL FORENSICS & REPRODUCTION -->
              <details class="tech-details" open>
                <summary class="tech-summary">🔬 Technical Forensics & Reproduction</summary>
                <p class="desc" style="margin-top: 10px;">{html.escape(f.description)}</p>
                <div class="meta-row">
                  <div><strong>Endpoint:</strong> <code>{html.escape(f.http_method)} {html.escape(f.affected_url)}</code></div>
                  <div><strong>Parameter:</strong> <code>{html.escape(f.affected_parameter or 'None')}</code></div>
                  <div><strong>OWASP:</strong> {html.escape(f.owasp_top10)}</div>
                  <div><strong>CVSS 3.1:</strong> <code>{html.escape(f.cvss.vector_string)}</code></div>
                  <div><strong>Evidence Hash:</strong> <code>{html.escape(f.evidence.proof_hash)}</code></div>
                </div>
                <h4 style="margin-top: 14px; font-size: 13px; color: #94a3b8;">🧪 Verified Proof of Concept (cURL Reproduction)</h4>
                <div class="code-block"><pre><code>{html.escape(f.evidence.curl_reproduction)}</code></pre></div>
              </details>

              <!-- REMEDIATION GUIDANCE -->
              <div class="remediation-box">
                <h4>🛠️ How to Fix (Remediation Guidance)</h4>
                <p style="margin: 6px 0 10px 0; color: #cbd5e1;">{html.escape(f.remediation_advice)}</p>
                {code_sample_html}
              </div>
            </div>
            """

        gate_html = ""
        for qg in report.quality_gates:
            gate_html += f"""
            <div class="gate-pill">
              <span class="gate-status {qg.status.value.lower()}">{qg.status.value}</span>
              <div class="gate-info">
                <div class="gate-title">{html.escape(qg.wave_name)}</div>
                <div class="gate-stats">Coverage: {qg.coverage_score}% | Tested: {qg.attack_surfaces_tested}/{qg.total_attack_surfaces} | Verified Findings: {qg.findings_verified}</div>
              </div>
            </div>
            """

        threat_model_html = ""
        tm_data = report.threat_model
        if tm_data and isinstance(tm_data, dict) and tm_data.get("threats"):
            tm_threats = tm_data.get("threats", [])
            tm_rows = ""
            for t in tm_threats:
                cat = html.escape(str(t.get("category", "")))
                title = html.escape(str(t.get("title", "")))
                risk = str(t.get("risk_level", "HIGH")).upper()
                desc = html.escape(str(t.get("description", "")))
                mitig = html.escape(str(t.get("mitigation_strategy", "")))
                comps = html.escape(", ".join(t.get("affected_components", [])[:3]))
                risk_color = "#ef4444" if risk == "CRITICAL" else ("#f97316" if risk == "HIGH" else "#eab308")

                tm_rows += f"""
                <div class="tm-card">
                  <div class="tm-header">
                    <span class="tm-badge">{cat}</span>
                    <span class="tm-risk" style="color: {risk_color};">{risk}</span>
                    <strong style="color: #fff; font-size: 14px;">{title}</strong>
                  </div>
                  <p style="font-size: 13px; color: #cbd5e1; margin: 6px 0;">{desc}</p>
                  <div style="font-size: 12px; color: #94a3b8; margin-bottom: 4px;"><strong>Surfaces:</strong> <code>{comps}</code></div>
                  <div style="font-size: 12px; color: #34d399;"><strong>Mitigation:</strong> {mitig}</div>
                </div>
                """

            threat_model_html = f"""
            <div class="card">
              <h2 style="margin-bottom: 14px; font-size: 18px; color: #fff;">🏛️ Microsoft STRIDE Architectural Threat Profile ({len(tm_threats)})</h2>
              <div class="tm-grid">
                {tm_rows}
              </div>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VAPT Assessment Dossier | {html.escape(report.report_id)}</title>
  <style>
    :root {{
      --bg: #070b13;
      --card-bg: #0f172a;
      --card-border: #1e293b;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #6366f1;
      --accent-glow: rgba(99, 102, 241, 0.15);
      --crit: #ef4444;
      --high: #f97316;
      --med: #eab308;
      --low: #3b82f6;
      --pass: #10b981;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg); color: var(--text-main); padding: 40px 20px; line-height: 1.6; }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    header {{ border-bottom: 1px solid var(--card-border); padding-bottom: 24px; margin-bottom: 32px; display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 16px; }}
    h1 {{ font-size: 26px; font-weight: 700; color: #fff; letter-spacing: -0.5px; }}
    .subtitle {{ color: var(--text-muted); font-size: 14px; margin-top: 4px; }}
    .grid-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 16px; margin-bottom: 28px; }}
    .stat-card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 10px; padding: 18px; }}
    .stat-val {{ font-size: 32px; font-weight: 700; }}
    .stat-lbl {{ color: var(--text-muted); font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }}
    .card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 24px; margin-bottom: 24px; }}
    
    /* Findings Styling */
    .finding-card {{ border-left: 5px solid var(--accent); transition: transform 0.15s ease; }}
    .finding-card.severity-critical {{ border-left-color: var(--crit); }}
    .finding-card.severity-high {{ border-left-color: var(--high); }}
    .finding-card.severity-medium {{ border-left-color: var(--med); }}
    .finding-card.severity-low {{ border-left-color: var(--low); }}
    
    .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; flex-wrap: wrap; gap: 10px; }}
    .header-left {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
    .finding-title {{ font-size: 18px; color: #fff; font-weight: 600; }}
    .badge {{ font-size: 12px; font-weight: 700; padding: 4px 10px; border-radius: 6px; }}
    .badge-outline {{ border: 1px solid var(--card-border); color: var(--text-muted); }}
    .finding-id {{ color: var(--text-muted); font-family: monospace; font-size: 13px; }}

    /* Non-Technical Callout */
    .section-box {{ border-radius: 8px; padding: 16px; margin: 16px 0; }}
    .plain-english-box {{ background: rgba(99, 102, 241, 0.08); border: 1px solid rgba(99, 102, 241, 0.25); }}
    .box-title {{ font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }}
    .plain-english-box .box-title {{ color: #818cf8; }}
    .plain-summary-text {{ font-size: 15px; color: #e2e8f0; line-height: 1.6; margin-bottom: 12px; }}
    
    .flaw-callout {{ background: rgba(15, 23, 42, 0.6); border-radius: 6px; padding: 12px; }}
    .callout-item {{ display: flex; flex-direction: column; gap: 4px; font-size: 14px; }}
    .callout-lbl {{ font-weight: 700; color: #94a3b8; font-size: 12px; text-transform: uppercase; }}
    .callout-val {{ color: #f8fafc; font-size: 14px; }}
    .flaw-highlight {{ color: #38bdf8; font-family: 'Consolas', monospace; }}
    .impact-highlight {{ color: #f87171; font-weight: 500; }}

    /* Exploit Scenario */
    .exploit-box {{ background: rgba(239, 68, 68, 0.06); border: 1px solid rgba(239, 68, 68, 0.2); }}
    .exploit-box .box-title {{ color: #f87171; }}
    .exploit-chain {{ display: flex; flex-direction: column; gap: 8px; }}
    .exploit-step {{ display: flex; gap: 10px; align-items: flex-start; font-size: 14px; color: #e2e8f0; }}
    .step-icon {{ color: #fbbf24; font-size: 14px; flex-shrink: 0; margin-top: 2px; }}
    .step-desc {{ line-height: 1.5; }}

    /* Technical Details & PoC */
    .tech-details {{ background: #090e17; border: 1px solid var(--card-border); border-radius: 8px; padding: 14px; margin: 16px 0; }}
    .tech-summary {{ cursor: pointer; font-weight: 600; font-size: 14px; color: #a5b4fc; outline: none; }}
    .meta-row {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; background: rgba(0,0,0,0.3); padding: 12px; border-radius: 6px; margin: 12px 0; font-size: 13px; }}
    .code-block {{ background: #030712; border: 1px solid #1e293b; border-radius: 6px; padding: 12px; margin: 10px 0; overflow-x: auto; }}
    code {{ font-family: 'Consolas', 'Menlo', 'Courier New', monospace; font-size: 13px; color: #a5b4fc; }}
    
    /* Remediation */
    .remediation-box {{ background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 8px; padding: 16px; margin-top: 16px; }}
    .remediation-box h4 {{ color: #34d399; font-size: 14px; margin-bottom: 6px; }}

    /* Filter Bar */
    .filter-bar {{ display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }}
    .filter-btn {{ background: var(--card-bg); border: 1px solid var(--card-border); color: var(--text-muted); padding: 8px 16px; border-radius: 20px; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.2s; }}
    .filter-btn:hover, .filter-btn.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}

    /* Quality Gates */
    .gate-pill {{ display: flex; align-items: center; gap: 16px; background: #0b1120; border: 1px solid var(--card-border); padding: 12px 16px; border-radius: 8px; margin-bottom: 10px; }}
    .gate-status {{ font-size: 12px; font-weight: 700; padding: 4px 10px; border-radius: 4px; }}
    .gate-status.passed {{ background: rgba(16, 185, 129, 0.2); color: #34d399; }}
    .gate-status.warning {{ background: rgba(234, 179, 8, 0.2); color: #facc15; }}
    .gate-status.failed {{ background: rgba(239, 68, 68, 0.2); color: #f87171; }}
    .gate-title {{ font-weight: 600; font-size: 14px; }}
    .gate-stats {{ color: var(--text-muted); font-size: 12px; }}

    /* STRIDE Threat Model Grid */
    .tm-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 14px; margin-top: 10px; }}
    .tm-card {{ background: #090e17; border: 1px solid var(--card-border); border-radius: 8px; padding: 14px; }}
    .tm-header {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 6px; }}
    .tm-badge {{ font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; background: rgba(99, 102, 241, 0.2); color: #818cf8; }}
    .tm-risk {{ font-size: 11px; font-weight: 700; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>🛡️ AI-Powered Penetration Testing Orchestrator</h1>
        <div class="subtitle">Multi-Agent VAPT Autonomous Security Report • <span style="color: #818cf8; font-weight: 600;">by Harshit Nigam</span> • <code>{html.escape(report.report_id)}</code></div>
      </div>
      <div style="text-align: right; color: var(--text-muted); font-size: 13px;">
        Target: <strong style="color: #fff;">{html.escape(report.target.target_url)}</strong><br>
        Audit Timestamp: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
      </div>
    </header>

    <div class="grid-stats">
      <div class="stat-card">
        <div class="stat-val" style="color: var(--crit);">{report.summary.critical_count}</div>
        <div class="stat-lbl">Critical Flaws</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: var(--high);">{report.summary.high_count}</div>
        <div class="stat-lbl">High Severity</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: var(--med);">{report.summary.medium_count}</div>
        <div class="stat-lbl">Medium Severity</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: var(--accent);">{report.summary.mean_cvss}</div>
        <div class="stat-lbl">Mean CVSS 3.1</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: var(--pass);">{report.summary.coverage_rate}%</div>
        <div class="stat-lbl">Attack Surface Coverage</div>
      </div>
    </div>

    <div class="card">
      <h2 style="margin-bottom: 12px; font-size: 18px; color: #fff;">📊 Executive Summary & Posture</h2>
      <pre style="white-space: pre-wrap; font-family: inherit; color: var(--text-muted); font-size: 14px;">{html.escape(report.executive_overview)}</pre>
    </div>

    <div class="card">
      <h2 style="margin-bottom: 16px; font-size: 18px; color: #fff;">🚪 Autonomous Quality Gate Verification</h2>
      {gate_html}
    </div>

    {threat_model_html}

    <div style="display: flex; justify-content: space-between; align-items: center; margin: 32px 0 16px 0; flex-wrap: wrap; gap: 12px;">
      <h2 style="font-size: 20px; color: #fff;">🔍 Verified Vulnerability Findings ({len(report.findings)})</h2>
      <div class="filter-bar">
        <button class="filter-btn active" onclick="filterFindings('ALL')">All ({len(report.findings)})</button>
        <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical ({report.summary.critical_count})</button>
        <button class="filter-btn" onclick="filterFindings('HIGH')">High ({report.summary.high_count})</button>
        <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium ({report.summary.medium_count})</button>
        <button class="filter-btn" onclick="filterFindings('LOW')">Low ({report.summary.low_count})</button>
      </div>
    </div>

    <div id="findings-container">
      {findings_html}
    </div>

    <footer style="margin-top: 50px; padding: 24px 0; border-top: 1px solid var(--card-border); text-align: center; color: var(--text-muted); font-size: 13px;">
      🛡️ AI-Powered Penetration Testing Orchestrator • Developed & Engineered <strong style="color: #a5b4fc;">by Harshit Nigam</strong>
    </footer>
  </div>

  <script>
    function filterFindings(severity) {{
      const cards = document.querySelectorAll('.finding-card');
      const buttons = document.querySelectorAll('.filter-btn');
      
      buttons.forEach(btn => {{
        if (btn.innerText.toUpperCase().startsWith(severity)) {{
          btn.classList.add('active');
        }} else {{
          btn.classList.remove('active');
        }}
      }});

      cards.forEach(card => {{
        const cardSev = card.getAttribute('data-severity');
        if (severity === 'ALL' || cardSev === severity) {{
          card.style.display = 'block';
        }} else {{
          card.style.display = 'none';
        }}
      }});
    }}
  </script>
</body>
</html>
"""
        with open(path, "w", encoding="utf-8") as out:
            out.write(html_content)
