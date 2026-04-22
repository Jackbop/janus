"""
Janus - Impact Report Generator
Genera report professionali in Markdown e HTML per bug bounty submissions.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Union
from modules.idor.detector import IDORFinding, Severity
from modules.business_logic.analyzer import BizLogicFinding


CVSS_MAP = {
    "CRITICAL": ("9.8", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "HIGH":     ("8.1", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "MEDIUM":   ("5.4", "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"),
    "INFO":     ("0.0", ""),
}

BOUNTY_ESTIMATES = {
    "CRITICAL": "💰 $3,000 – $15,000+",
    "HIGH":     "💰 $500 – $3,000",
    "MEDIUM":   "💰 $100 – $500",
    "INFO":     "💰 Non eligibile",
}


class ImpactReporter:
    """
    Converte i finding di Janus in report pronti per HackerOne / Bugcrowd.
    Formato: Markdown (per invio) + HTML (per preview visuale).
    """

    def __init__(self, target: str, tester: str = "Janus Auto"):
        self.target = target
        self.tester = tester
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        self.all_findings: list[Union[IDORFinding, BizLogicFinding]] = []

    def add_idor_findings(self, findings: list[IDORFinding]):
        self.all_findings.extend(findings)

    def add_bizlogic_findings(self, findings: list[BizLogicFinding]):
        self.all_findings.extend(findings)

    def generate_markdown(self, output_path: str = "janus_report.md") -> str:
        lines = [
            f"# 🛡️ Janus Security Report",
            f"**Target:** `{self.target}`  ",
            f"**Date:** {self.timestamp}  ",
            f"**Tester:** {self.tester}  ",
            f"**Total Findings:** {len(self.all_findings)}",
            "",
            "---",
            "",
        ]

        # Executive Summary
        critical = sum(1 for f in self.all_findings if self._severity(f) == "CRITICAL")
        high = sum(1 for f in self.all_findings if self._severity(f) == "HIGH")
        medium = sum(1 for f in self.all_findings if self._severity(f) == "MEDIUM")

        lines += [
            "## 📊 Executive Summary",
            "",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| 🔴 Critical | {critical} |",
            f"| 🟠 High | {high} |",
            f"| 🟡 Medium | {medium} |",
            "",
            "---",
            "",
            "## 🔍 Findings",
            "",
        ]

        for i, finding in enumerate(self.all_findings, 1):
            lines += self._finding_to_markdown(finding, i)

        content = "\n".join(lines)
        Path(output_path).write_text(content, encoding="utf-8")
        print(f"[✅] Report Markdown salvato: {output_path}")
        return content

    def generate_html(self, output_path: str = "janus_report.html") -> str:
        findings_html = "".join(self._finding_to_html(f, i)
                                for i, f in enumerate(self.all_findings, 1))

        critical = sum(1 for f in self.all_findings if self._severity(f) == "CRITICAL")
        high = sum(1 for f in self.all_findings if self._severity(f) == "HIGH")
        medium = sum(1 for f in self.all_findings if self._severity(f) == "MEDIUM")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Janus Report – {self.target}</title>
<style>
  :root {{
    --bg: #0a0e1a; --surface: #111827; --border: #1e2a3a;
    --text: #e2e8f0; --muted: #64748b;
    --red: #ef4444; --orange: #f97316; --yellow: #eab308;
    --green: #22c55e; --blue: #3b82f6;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', monospace; padding: 2rem; }}
  h1 {{ font-size: 2rem; color: var(--blue); margin-bottom: 0.5rem; }}
  .meta {{ color: var(--muted); margin-bottom: 2rem; font-size: 0.85rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; }}
  .badge {{ padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: bold; font-size: 1.1rem; }}
  .badge.critical {{ background: #7f1d1d; color: var(--red); }}
  .badge.high {{ background: #7c2d12; color: var(--orange); }}
  .badge.medium {{ background: #713f12; color: var(--yellow); }}
  .finding {{ background: var(--surface); border: 1px solid var(--border);
              border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .finding-header {{ display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }}
  .severity-badge {{ padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
  .CRITICAL {{ background: #7f1d1d; color: var(--red); }}
  .HIGH {{ background: #7c2d12; color: var(--orange); }}
  .MEDIUM {{ background: #713f12; color: var(--yellow); }}
  .finding h2 {{ font-size: 1.1rem; }}
  .section-label {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase;
                    letter-spacing: 0.1em; margin: 1rem 0 0.25rem; }}
  .code-block {{ background: #0f172a; border: 1px solid var(--border); border-radius: 6px;
                 padding: 0.75rem; font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap;
                 color: #93c5fd; }}
  .steps ol {{ padding-left: 1.5rem; }}
  .steps li {{ margin: 0.25rem 0; font-size: 0.9rem; }}
  .impact-box {{ background: #1a0a0a; border-left: 3px solid var(--red);
                 padding: 0.75rem 1rem; border-radius: 0 6px 6px 0; font-size: 0.9rem; }}
  .cvss {{ color: var(--muted); font-size: 0.8rem; margin-top: 0.5rem; }}
  .bounty {{ color: var(--green); font-size: 0.85rem; margin-top: 0.25rem; }}
</style>
</head>
<body>
<h1>🛡️ Janus Security Report</h1>
<div class="meta">Target: <strong>{self.target}</strong> | Date: {self.timestamp} | Tester: {self.tester}</div>
<div class="summary">
  <div class="badge critical">🔴 Critical: {critical}</div>
  <div class="badge high">🟠 High: {high}</div>
  <div class="badge medium">🟡 Medium: {medium}</div>
</div>
{findings_html}
</body>
</html>"""
        Path(output_path).write_text(html, encoding="utf-8")
        print(f"[✅] Report HTML salvato: {output_path}")
        return html

    def generate_hackerone_submission(self, finding_index: int = 0) -> str:
        """Genera il testo formattato per la submission su HackerOne."""
        if finding_index >= len(self.all_findings):
            return "Nessun finding disponibile."
        f = self.all_findings[finding_index]
        sev = self._severity(f)
        cvss_score, cvss_vector = CVSS_MAP.get(sev, ("5.0", ""))

        lines = [
            f"## Vulnerability: {self._title(f)}",
            "",
            f"**Severity:** {sev} (CVSS {cvss_score})",
            f"**Endpoint:** `{f.endpoint}`",
            f"**Method:** {f.method}",
            "",
            "## Summary",
            self._description(f),
            "",
            "## Steps to Reproduce",
        ]
        for step in self._steps(f):
            lines.append(step)
        lines += [
            "",
            "## Impact",
            self._impact(f),
            "",
            "## Supporting Material",
            f"```",
            f"Request: {self._payload(f)}",
            f"Response (snippet): {self._snippet(f)[:300]}",
            f"```",
        ]
        return "\n".join(lines)

    # ──────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────

    def _severity(self, f) -> str:
        if isinstance(f, IDORFinding):
            return f.severity.value
        return f.severity

    def _title(self, f) -> str:
        if isinstance(f, IDORFinding):
            return f"IDOR on {f.endpoint} via `{f.param}` parameter"
        return f"{f.vuln_type.value} on {f.endpoint}"

    def _description(self, f) -> str:
        if isinstance(f, IDORFinding):
            return (f"The `{f.param}` parameter on `{f.endpoint}` is vulnerable to IDOR. "
                    f"User `{f.attacker_account}` can access resources belonging to "
                    f"`{f.victim_account}` by changing `{f.param}` to `{f.victim_id}`. "
                    f"Sensitive fields exposed: {f.leaked_fields}")
        return f.description

    def _steps(self, f) -> list[str]:
        if isinstance(f, IDORFinding):
            return [
                f"1. Login as attacker (`{f.attacker_account}`)",
                f"2. Send `{f.method}` request to `{f.endpoint}` with `{f.param}={f.victim_id}`",
                "3. Observe that the response contains victim's sensitive data",
                f"4. Leaked fields: {f.leaked_fields}",
            ]
        return f.reproduction_steps

    def _impact(self, f) -> str:
        if isinstance(f, IDORFinding):
            return (f"Any authenticated user can access, modify, or delete any other user's "
                    f"private data by simply changing the `{f.param}` value. "
                    f"Leaked data includes: {f.leaked_fields}.")
        return f.impact

    def _payload(self, f) -> str:
        if isinstance(f, IDORFinding):
            return f.request_payload
        return f.request_payload

    def _snippet(self, f) -> str:
        if isinstance(f, IDORFinding):
            return f.response_snippet
        return f.response_snippet

    def _finding_to_markdown(self, f, index: int) -> list[str]:
        sev = self._severity(f)
        cvss_score, _ = CVSS_MAP.get(sev, ("5.0", ""))
        bounty = BOUNTY_ESTIMATES.get(sev, "")
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(sev, "⚪")

        lines = [
            f"### {index}. {emoji} [{sev}] {self._title(f)}",
            "",
            f"**CVSS Score:** {cvss_score}  ",
            f"**Estimated Bounty:** {bounty}  ",
            f"**Endpoint:** `{f.endpoint}`  ",
            f"**Method:** `{f.method}`",
            "",
            "**Description:**",
            self._description(f),
            "",
            "**Steps to Reproduce:**",
        ]
        for step in self._steps(f):
            lines.append(step)
        lines += [
            "",
            "**Impact:**",
            self._impact(f),
            "",
            "**Evidence:**",
            f"```",
            f"Request: {self._payload(f)}",
            f"Response: {self._snippet(f)[:200]}",
            f"```",
            "",
            "---",
            "",
        ]
        return lines

    def _finding_to_html(self, f, index: int) -> str:
        sev = self._severity(f)
        cvss_score, _ = CVSS_MAP.get(sev, ("5.0", ""))
        bounty = BOUNTY_ESTIMATES.get(sev, "")
        steps_html = "".join(f"<li>{s}</li>" for s in self._steps(f))

        return f"""
<div class="finding">
  <div class="finding-header">
    <span class="severity-badge {sev}">{sev}</span>
    <h2>{index}. {self._title(f)}</h2>
  </div>
  <div class="cvss">CVSS Score: {cvss_score} | Endpoint: <code>{f.endpoint}</code> [{f.method}]</div>
  <div class="bounty">{bounty}</div>
  <div class="section-label">Description</div>
  <p style="font-size:0.9rem">{self._description(f)}</p>
  <div class="section-label">Impact</div>
  <div class="impact-box">{self._impact(f)}</div>
  <div class="section-label">Steps to Reproduce</div>
  <div class="steps"><ol>{steps_html}</ol></div>
  <div class="section-label">Evidence</div>
  <div class="code-block">Request: {self._payload(f)}\n\nResponse:\n{self._snippet(f)[:300]}</div>
</div>"""
