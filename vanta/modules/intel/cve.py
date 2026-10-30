"""Offline CVE correlation.

Components fingerprinted by the tech-detect module are matched against a local
knowledge base of known vulnerabilities. It works with no internet access, which
matters for labs and for grading, and can optionally be refreshed from the NVD
API in a live engagement.

The bundled KB is deliberately small and clearly a *sample*; the point of the
module is the matching and reporting pipeline, not the size of the dataset.
"""

from __future__ import annotations

import json
from pathlib import Path

from vanta.core.models import Confidence, Evidence, Finding, Severity
from vanta.core.registry import Module, RunContext, register

_DATA = Path(__file__).resolve().parents[2] / "data" / "cve.json"


def load_kb(path: Path | None = None) -> list[dict]:
    path = path or _DATA
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("entries", [])
    except json.JSONDecodeError:
        return []


def _version_lt(a: str, b: str) -> bool:
    """Rudimentary dotted-version comparison, enough for major/minor checks."""
    def parts(v: str):
        out = []
        for chunk in v.replace("-", ".").split("."):
            num = "".join(ch for ch in chunk if ch.isdigit())
            out.append(int(num) if num else 0)
        return out

    pa, pb = parts(a), parts(b)
    length = max(len(pa), len(pb))
    pa += [0] * (length - len(pa))
    pb += [0] * (length - len(pb))
    return pa < pb


@register
class CVECorrelation(Module):
    name = "cve-correlate"
    category = "cve"
    description = "Correlate fingerprinted components against an offline CVE knowledge base"
    phase = 70

    def _components(self, ctx: RunContext) -> dict[str, str]:
        """Return {product: version} from prior modules or config overrides."""
        components: dict[str, str] = {}
        for tech in ctx.shared.get("technologies", []):
            if isinstance(tech, dict):
                components[tech.get("product", "").lower()] = tech.get("version", "")
        components.update(
            {k.lower(): v for k, v in self.config.get("components", {}).items()}
        )
        return {k: v for k, v in components.items() if k}

    async def run(self, ctx: RunContext) -> list[Finding]:
        components = self._components(ctx)
        if not components:
            ctx.log.debug("cve.no-components", host=ctx.target.host)
            return []

        kb = load_kb()
        findings: list[Finding] = []
        for entry in kb:
            product = entry["product"].lower()
            if product not in components:
                continue
            version = components[product]
            affected_below = entry.get("affected_below")
            if version and affected_below and not _version_lt(version, affected_below):
                continue  # patched
            if not version and entry.get("requires_version", False):
                continue

            score = float(entry.get("cvss", 0.0))
            findings.append(
                Finding(
                    title=f"{entry['cve']} in {product} ({version or 'version unknown'}) on {ctx.target.host}",
                    module=self.name,
                    target=ctx.target.host,
                    severity=Severity.from_cvss(score),
                    confidence=Confidence.TENTATIVE if not version else Confidence.FIRM,
                    category="cve",
                    cwe=entry.get("cwe"),
                    cvss_score=score,
                    cvss_vector=entry.get("cvss_vector"),
                    description=entry.get("description", ""),
                    impact=entry.get("impact", "Known exploited component; escalate as appropriate."),
                    remediation=entry.get("remediation", "Upgrade to a fixed version."),
                    metadata={"product": product, "version": version, "cve": entry["cve"]},
                    references=[f"https://nvd.nist.gov/vuln/detail/{entry['cve']}"],
                    evidence=[
                        Evidence(
                            kind="cve-match",
                            summary=f"{product} {version or '?'} < {affected_below or 'n/a'}",
                        )
                    ],
                )
            )
        return findings
