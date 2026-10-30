"""SQL injection detection.

Technique: error-based detection using database-specific error signatures,
followed by a boolean-differential probe to reduce false positives. Payloads are
non-destructive reads (``'``, ``AND 1=1`` vs ``AND 1=2``) - no UNION dumps, no
stacked queries, no writes. The number of requests is capped and rate limited.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from vanta.core.models import Confidence, Evidence, Finding, Severity
from vanta.core.registry import Module, RunContext, register
from vanta.core.scoring import cvss_base_score
from vanta.modules.vuln._util import injection_points

_ERROR_SIGNATURES = [
    (re.compile(r"SQL syntax.*MySQL", re.I), "MySQL"),
    (re.compile(r"Warning.*\Wmysqli?_", re.I), "MySQL"),
    (re.compile(r"PostgreSQL.*ERROR", re.I), "PostgreSQL"),
    (re.compile(r"ORA-\d{5}", re.I), "Oracle"),
    (re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I), "MSSQL"),
    (re.compile(r"Unclosed quotation mark after the character string", re.I), "MSSQL"),
    (re.compile(r"SQLite/JDBCDriver|SQLite\.Exception", re.I), "SQLite"),
    (re.compile(r"quoted string not properly terminated", re.I), "Oracle"),
]


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


@register
class SQLInjection(Module):
    name = "sqli"
    category = "injection"
    description = "Error- and boolean-based SQL injection detection on URL parameters"
    active = True
    phase = 60

    async def run(self, ctx: RunContext) -> list[Finding]:
        points = injection_points(ctx)
        if not points:
            return []

        findings: list[Finding] = []
        for url, param in points:
            injected = _with_param(url, param, "1'")
            resp = await ctx.http.get(injected)
            if not resp.ok:
                continue

            hit = next(
                ((name, sig) for sig, name in _ERROR_SIGNATURES if sig.search(resp.text)),
                None,
            )
            if hit:
                db, pattern = hit
                findings.append(
                    Finding(
                        title=f"SQL injection in parameter '{param}' on {ctx.target.host}",
                        module=self.name,
                        target=ctx.target.host,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="injection",
                        cwe="CWE-89",
                        owasp="A03:2021 Injection",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cvss_score=cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                        description=(
                            f"A single quote in `{param}` produced a {db} error matching "
                            f"`{pattern.pattern}` — strong evidence of unsanitised SQL."
                        ),
                        impact=(
                            "An attacker can read, modify or delete database contents and, with "
                            "sufficient privileges, execute code on the database host."
                        ),
                        remediation=(
                            "Use parameterised queries / prepared statements. Never concatenate "
                            "user input into SQL. Apply least-privilege DB accounts."
                        ),
                        metadata={"parameter": param, "dbms": db},
                        references=["https://owasp.org/Top10/A03_2021-Injection/"],
                        evidence=[
                            Evidence(
                                kind="http-sqli",
                                summary=f"{injected} -> error signature: {db}",
                                sha256=Evidence.hash_bytes(resp.body),
                            )
                        ],
                    )
                )
                continue

            # Boolean differential: 1=1 vs 1=2 should differ if injectable.
            true_resp = await ctx.http.get(_with_param(url, param, "1 AND 1=1"))
            false_resp = await ctx.http.get(_with_param(url, param, "1 AND 1=2"))
            if (
                true_resp.ok and false_resp.ok
                and abs(len(true_resp.body) - len(false_resp.body)) > 32
                and true_resp.status == false_resp.status
            ):
                findings.append(
                    Finding(
                        title=f"Possible boolean-based SQL injection in '{param}'",
                        module=self.name,
                        target=ctx.target.host,
                        severity=Severity.HIGH,
                        confidence=Confidence.TENTATIVE,
                        category="injection",
                        cwe="CWE-89",
                        owasp="A03:2021 Injection",
                        description=(
                            f"Responses to `AND 1=1` vs `AND 1=2` differ in length "
                            f"({len(true_resp.body)} vs {len(false_resp.body)} bytes), "
                            "suggesting the parameter influences a SQL predicate."
                        ),
                        impact="Same as confirmed SQL injection; verify manually before reporting.",
                        remediation="Parameterise queries and validate input types.",
                        metadata={"parameter": param},
                        evidence=[
                            Evidence(
                                kind="http-sqli-diff",
                                summary=f"1=1 -> {len(true_resp.body)}B, 1=2 -> {len(false_resp.body)}B",
                            )
                        ],
                    )
                )
        return findings
