"""SSRF detection with an out-of-band canary strategy.

Rather than hitting real internal services, we substitute a callback URL (or a
loopback address) into candidate parameters and look for behavioural signals:
a different status/length, or a reflected hostname. This proves *the parameter
is fetched server-side* without pivoting. Works best with a collaborator URL set
in the engagement metadata as ``ssrf_callback``.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from vanta.core.models import Confidence, Evidence, Finding, Severity
from vanta.core.registry import Module, RunContext, register
from vanta.core.scoring import cvss_base_score
from vanta.modules.vuln._util import injection_points

_URL_HINT_PARAMS = {
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect",
    "next", "target", "callback", "image", "img", "fetch", "load", "file",
    "page", "host", "domain", "feed", "proxy", "webhook",
}


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


@register
class SSRF(Module):
    name = "ssrf"
    category = "ssrf"
    description = "Server-side request forgery detection using a callback canary"
    active = True
    phase = 64

    async def run(self, ctx: RunContext) -> list[Finding]:
        points = [
            (url, param)
            for url, param in injection_points(ctx)
            if param.lower() in _URL_HINT_PARAMS or "url" in param.lower()
        ]
        if not points:
            return []

        callback = self.config.get("ssrf_callback", "http://127.0.0.1:1/vanta-canary")
        baseline = await ctx.http.get(ctx.base_url)
        if not baseline.ok:
            return []

        findings: list[Finding] = []
        for url, param in points[:8]:
            injected = _with_param(url, param, callback)
            resp = await ctx.http.get(injected, follow_redirects=False)
            if not resp.ok:
                continue
            changed = (
                resp.status != baseline.status
                or abs(len(resp.body) - len(baseline.body)) > 64
                or "127.0.0.1" in resp.text
            )
            if changed:
                findings.append(
                    Finding(
                        title=f"Potential SSRF in parameter '{param}' on {ctx.target.host}",
                        module=self.name,
                        target=ctx.target.host,
                        severity=Severity.HIGH,
                        confidence=Confidence.TENTATIVE,
                        category="ssrf",
                        cwe="CWE-918",
                        owasp="A10:2021 Server-Side Request Forgery",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
                        cvss_score=cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"),
                        description=(
                            f"Substituting `{param}` with `{callback}` changed the response "
                            f"(status {baseline.status}->{resp.status}, "
                            f"length {len(baseline.body)}->{len(resp.body)}B), suggesting the "
                            "server fetches the supplied URL."
                        ),
                        impact=(
                            "SSRF can reach internal services, cloud metadata endpoints "
                            "(169.254.169.254) and bypass network segmentation."
                        ),
                        remediation=(
                            "Allow-list outbound destinations, block link-local/metadata ranges, "
                            "and never fetch user-supplied URLs directly."
                        ),
                        metadata={"parameter": param, "callback": callback},
                        references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
                        evidence=[
                            Evidence(
                                kind="http-ssrf",
                                summary=f"{injected} -> status {resp.status}, {len(resp.body)}B",
                            )
                        ],
                    )
                )
        return findings
