"""Markdown renderer.

Deliberately the *primary* output format: Markdown diffs cleanly in git, reads
well in a terminal, and converts to PDF for submission. The structure mirrors a
professional pentest report so the same document serves the dissertation and a
real client.
"""

from __future__ import annotations

import time
from collections import defaultdict

from vanta.core.attck import coverage_matrix, describe
from vanta.core.models import Finding, Severity

_SEV_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def _fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


def render_markdown(report) -> str:
    eng = report.engagement
    risk = report.risk
    out: list[str] = []

    out.append(f"# Penetration Test Report — {eng.name}")
    out.append("")
    out.append(f"- **Client / Programme:** {eng.client or '—'}")
    out.append(f"- **Authorisation reference:** {eng.authorisation_reference or '—'}")
    out.append(f"- **Generated:** {_fmt_ts(report.finished_at or time.time())}")
    out.append(f"- **Duration:** {report.duration:.1f}s")
    out.append(f"- **Targets tested:** {len(report.targets)}")
    out.append(f"- **Findings:** {len(report.findings)}")
    if risk:
        out.append(f"- **Engagement risk score:** {risk.score:.1f}/100 (grade **{risk.grade}**)")
    out.append("")

    out.append("## 1. Executive Summary")
    out.append("")
    if risk and report.findings:
        out.append(
            f"VANTA identified **{len(report.findings)}** findings across "
            f"{len(report.targets)} target(s). The aggregate risk score is "
            f"**{risk.score:.1f}/100** (grade **{risk.grade}**). "
            "The most significant issues are listed below; each is rated by CVSS v3.1 "
            "base score where a vector is available and mapped to MITRE ATT&CK."
        )
    else:
        out.append("No findings were recorded for this engagement.")
    out.append("")

    if risk:
        out.append("### Severity breakdown")
        out.append("")
        out.append("| Severity | Count |")
        out.append("|---|---|")
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            out.append(f"| {_SEV_ICON[sev]} {sev.value.title()} | {risk.severity_counts[sev.value]} |")
        out.append("")

    # Attack paths - the differentiator versus a flat scanner.
    if report.paths:
        out.append("## 2. Attack Paths")
        out.append("")
        out.append("Chained exploitation routes ranked by combined risk:")
        out.append("")
        for host, paths in report.paths.items():
            out.append(f"### {host}")
            for i, p in enumerate(paths, 1):
                out.append(f"{i}. `{p.describe()}` — combined risk {p.risk:.1f}")
            out.append("")

    # Findings.
    out.append("## 3. Findings")
    out.append("")
    groups: dict[Severity, list[Finding]] = defaultdict(list)
    for f in report.findings:
        groups[f.severity].append(f)

    idx = 0
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        for f in groups.get(sev, []):
            idx += 1
            out.append(f"### 3.{idx} {_SEV_ICON[sev]} {f.title}")
            out.append("")
            out.append(f"| Field | Value |")
            out.append("|---|---|")
            out.append(f"| Severity | {f.severity.value.title()} |")
            out.append(f"| Confidence | {f.confidence.value.title()} |")
            out.append(f"| Target | `{f.target}` |")
            out.append(f"| Module | `{f.module}` |")
            if f.cvss_score is not None:
                out.append(f"| CVSS v3.1 | {f.cvss_score} (`{f.cvss_vector}`) |")
            if f.cwe:
                out.append(f"| CWE | {f.cwe} |")
            if f.owasp:
                out.append(f"| OWASP | {f.owasp} |")
            if f.attck:
                out.append(f"| ATT&CK | {', '.join(describe(t) for t in f.attck)} |")
            out.append("")
            if f.description:
                out.append(f.description.strip())
                out.append("")
            if f.impact:
                out.append(f"**Impact.** {f.impact.strip()}")
                out.append("")
            if f.evidence:
                out.append("**Evidence.**")
                out.append("")
                for ev in f.evidence:
                    suffix = f" (`{ev.path}`, sha256:{ev.sha256[:12]}…)" if ev.path else ""
                    out.append(f"- [{ev.kind}] {ev.summary}{suffix}")
                out.append("")
            if f.remediation:
                out.append(f"**Remediation.** {f.remediation.strip()}")
                out.append("")
            if f.references:
                out.append("**References.**")
                out.append("")
                for ref in f.references:
                    out.append(f"- <{ref}>")
                out.append("")

    # ATT&CK coverage matrix.
    matrix = coverage_matrix(report.findings)
    if matrix:
        out.append("## 4. MITRE ATT&CK Coverage")
        out.append("")
        out.append("| Tactic | Techniques observed |")
        out.append("|---|---|")
        for tactic, ids in matrix.items():
            out.append(f"| {tactic} | {', '.join(describe(t) for t in ids)} |")
        out.append("")

    # Methodology / module run log.
    out.append("## 5. Methodology & Module Log")
    out.append("")
    out.append("| Module | Findings | Status | Time (s) |")
    out.append("|---|---|---|---|")
    for r in report.module_results:
        status = "skipped" if r.skipped else ("error" if r.error else "ok")
        if r.skipped:
            status = f"skipped ({r.skip_reason})"
        out.append(f"| `{r.module}` | {len(r.findings)} | {status} | {r.duration:.2f} |")
    out.append("")
    out.append("---")
    out.append("")
    out.append(
        "*Generated by VANTA. All activity was restricted to the authorised scope; "
        "evidence artefacts are SHA-256 hashed with a chain-of-custody manifest.*"
    )
    out.append("")
    return "\n".join(out)
