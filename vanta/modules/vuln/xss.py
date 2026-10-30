"""Reflected XSS detection via a unique canary.

Sends a canary token in each parameter and checks whether it is reflected
unencoded in a script/HTML context. Detection only - no actual payload that
executes in a victim's browser, and no storage in the application.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from vanta.core.models import Confidence, Evidence, Finding, Severity
from vanta.core.registry import Module, RunContext, register
from vanta.core.scoring import cvss_base_score
from vanta.modules.vuln._util import injection_points


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


@register
class CrossSiteScripting(Module):
    name = "xss"
    category = "xss"
    description = "Reflected XSS detection using a non-executing canary token"
    active = True
    phase = 62

    async def run(self, ctx: RunContext) -> list[Finding]:
        points = injection_points(ctx)
        if not points:
            return []

        findings: list[Finding] = []
        for url, param in points:
            canary = "vanta" + secrets.token_hex(4)
            payload = f'"><svg/onload={canary}>'
            injected = _with_param(url, param, payload)
            resp = await ctx.http.get(injected)
            if not resp.ok:
                continue

            body = resp.text
            if payload in body:
                findings.append(
                    Finding(
                        title=f"Reflected XSS in parameter '{param}' on {ctx.target.host}",
                        module=self.name,
                        target=ctx.target.host,
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        category="xss",
                        cwe="CWE-79",
                        owasp="A03:2021 Injection",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        cvss_score=cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
                        description=(
                            f"The marker payload `{payload}` was reflected verbatim in the "
                            f"response for parameter `{param}`, without HTML encoding."
                        ),
                        impact=(
                            "An attacker can execute script in a victim's session, steal "
                            "cookies/tokens, or perform actions as the victim."
                        ),
                        remediation=(
                            "Context-aware output encoding, a strict Content-Security-Policy, "
                            "and input validation."
                        ),
                        metadata={"parameter": param, "payload": payload},
                        references=["https://owasp.org/www-community/attacks/xss/"],
                        evidence=[
                            Evidence(
                                kind="http-xss",
                                summary=f"{injected} reflected payload",
                                sha256=Evidence.hash_bytes(resp.body),
                            )
                        ],
                    )
                )
        return findings
