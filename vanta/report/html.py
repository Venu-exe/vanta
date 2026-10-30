"""Self-contained HTML renderer.

No CDN, no build step, no external CSS: the whole report is one portable file you
can email or attach to a dissertation. Severity colour coding and the attack-path
section are rendered inline.
"""

from __future__ import annotations

import html
import time
from collections import defaultdict

from vanta.core.attck import coverage_matrix, describe
from vanta.core.models import Severity

_SEV_CLASS = {
    Severity.CRITICAL: "sev-critical",
    Severity.HIGH: "sev-high",
    Severity.MEDIUM: "sev-medium",
    Severity.LOW: "sev-low",
    Severity.INFO: "sev-info",
}

_CSS = """
:root{--bg:#0f1115;--panel:#171a21;--fg:#e6e8ee;--muted:#9aa3b2;--line:#262b36}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:40px 22px 80px}
h1{font-size:28px;margin:0 0 4px}h2{margin-top:40px;border-bottom:1px solid var(--line);padding-bottom:8px}
h3{margin-top:28px}.meta{color:var(--muted);font-size:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:14px 0}
table{width:100%;border-collapse:collapse;margin:12px 0;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
code{background:#0b0d11;padding:2px 6px;border-radius:5px;font-size:13px}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:600}
.sev-critical{background:#5b1020;color:#ff8fa3}.sev-high{background:#5a2408;color:#ffb37a}
.sev-medium{background:#4a3c05;color:#ffe07a}.sev-low{background:#0d3550;color:#8fd0ff}
.sev-info{background:#2a2f3a;color:#c3cad6}
.score{font-size:44px;font-weight:700}.grade{font-size:20px;color:var(--muted)}
.path{font-family:ui-monospace,monospace;font-size:13px;color:#cbd5e1}
footer{margin-top:50px;color:var(--muted);font-size:13px;border-top:1px solid var(--line);padding-top:14px}
"""


def _e(v: object) -> str:
    return html.escape(str(v), quote=True)


def render_html(report) -> str:
    eng = report.engagement
    risk = report.risk
    generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(report.finished_at or time.time()))

    parts: list[str] = []
    parts.append("<!doctype html><html lang=en><head><meta charset=utf-8>")
    parts.append("<meta name=viewport content='width=device-width,initial-scale=1'>")
    parts.append(f"<title>VANTA Report — {_e(eng.name)}</title>")
    parts.append(f"<style>{_CSS}</style></head><body><div class=wrap>")

    parts.append(f"<h1>Penetration Test Report</h1>")
    parts.append(
        f"<p class=meta>{_e(eng.name)} · {_e(eng.client or '—')} · "
        f"auth: {_e(eng.authorisation_reference or '—')} · {_e(generated)}</p>"
    )

    if risk:
        parts.append("<div class=card>")
        parts.append(f"<div class=score>{risk.score:.1f}<span class=grade> /100 · grade {risk.grade}</span></div>")
        parts.append("<table><tr><th>Severity</th><th>Count</th></tr>")
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            parts.append(
                f"<tr><td><span class='badge {_SEV_CLASS[sev]}'>{sev.value}</span></td>"
                f"<td>{risk.severity_counts[sev.value]}</td></tr>"
            )
        parts.append("</table></div>")

    if report.paths:
        parts.append("<h2>Attack Paths</h2>")
        for host, paths in report.paths.items():
            parts.append(f"<h3>{_e(host)}</h3><div class=card>")
            for p in paths:
                parts.append(f"<div class=path>{_e(p.describe())} &nbsp;·&nbsp; risk {p.risk:.1f}</div>")
            parts.append("</div>")

    parts.append("<h2>Findings</h2>")
    groups: dict[Severity, list] = defaultdict(list)
    for f in report.findings:
        groups[f.severity].append(f)
    if not report.findings:
        parts.append("<div class=card>No findings recorded.</div>")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        for f in groups.get(sev, []):
            parts.append("<div class=card>")
            parts.append(f"<h3><span class='badge {_SEV_CLASS[sev]}'>{sev.value}</span> {_e(f.title)}</h3>")
            rows = [
                ("Target", f"<code>{_e(f.target)}</code>"),
                ("Module", f"<code>{_e(f.module)}</code>"),
                ("Confidence", _e(f.confidence.value)),
            ]
            if f.cvss_score is not None:
                rows.append(("CVSS v3.1", f"{f.cvss_score} <code>{_e(f.cvss_vector)}</code>"))
            if f.cwe:
                rows.append(("CWE", _e(f.cwe)))
            if f.attck:
                rows.append(("ATT&CK", _e(", ".join(describe(t) for t in f.attck))))
            parts.append("<table>")
            for k, v in rows:
                parts.append(f"<tr><th>{k}</th><td>{v}</td></tr>")
            parts.append("</table>")
            if f.description:
                parts.append(f"<p>{_e(f.description)}</p>")
            if f.impact:
                parts.append(f"<p><b>Impact.</b> {_e(f.impact)}</p>")
            if f.evidence:
                parts.append("<ul>")
                for ev in f.evidence:
                    parts.append(f"<li>[{_e(ev.kind)}] {_e(ev.summary)} <code>sha256:{_e(ev.sha256[:12])}…</code></li>")
                parts.append("</ul>")
            if f.remediation:
                parts.append(f"<p><b>Remediation.</b> {_e(f.remediation)}</p>")
            parts.append("</div>")

    matrix = coverage_matrix(report.findings)
    if matrix:
        parts.append("<h2>MITRE ATT&CK Coverage</h2><table><tr><th>Tactic</th><th>Techniques</th></tr>")
        for tactic, ids in matrix.items():
            parts.append(f"<tr><td>{_e(tactic)}</td><td>{_e(', '.join(describe(t) for t in ids))}</td></tr>")
        parts.append("</table>")

    parts.append("<h2>Module Log</h2><table><tr><th>Module</th><th>Findings</th><th>Status</th><th>Seconds</th></tr>")
    for r in report.module_results:
        status = "skipped: " + (r.skip_reason or "") if r.skipped else ("error: " + r.error if r.error else "ok")
        parts.append(
            f"<tr><td><code>{_e(r.module)}</code></td><td>{len(r.findings)}</td>"
            f"<td>{_e(status)}</td><td>{r.duration:.2f}</td></tr>"
        )
    parts.append("</table>")

    parts.append(
        "<footer>Generated by VANTA · activity restricted to the authorised scope · "
        "evidence SHA-256 hashed with chain-of-custody manifest</footer>"
    )
    parts.append("</div></body></html>")
    return "".join(parts)
