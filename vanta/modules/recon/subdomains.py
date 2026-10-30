"""Passive/active subdomain enumeration.

Given a scope host such as ``example.com`` this resolves a curated wordlist of
common subdomain labels plus a handful of environment/role names, and reports
every name that resolves but is *not* the apex. Only in-scope names are ever
tested because the engine hands the module a scoped HTTP client and we check the
scope ourselves before a DNS query.
"""

from __future__ import annotations

import asyncio

from vanta.core.models import Confidence, Evidence, Finding, Severity
from vanta.core.registry import Module, RunContext, register
from vanta.modules.recon._util import load_lines, resolve


@register
class SubdomainEnum(Module):
    name = "subdomains"
    category = "subdomain"
    description = "DNS brute-force enumeration of common subdomain labels"
    phase = 10

    # Labels that almost always exist and are worth reporting for context.
    INTERESTING = {
        "admin", "administrator", "portal", "vpn", "dev", "staging", "test",
        "git", "gitlab", "jenkins", "jira", "api", "internal", "intranet",
        "sso", "auth", "mail", "webmail", "backup", "db", "phpmyadmin",
    }

    def _candidates(self, host: str) -> list[str]:
        words = load_lines("subdomains.txt", limit=int(self.config.get("subdomain_limit", 200)))
        words = list(dict.fromkeys(words + list(self.INTERESTING)))
        return [f"{w}.{host}" for w in words]

    async def run(self, ctx: RunContext) -> list[Finding]:
        import ipaddress

        apex = ctx.target.host
        try:
            ipaddress.ip_address(apex)
            ctx.log.debug("subdomains.skip-ip", host=apex)
            return []  # DNS labels are meaningless against an IP literal
        except ValueError:
            pass

        scope = ctx.http.scope
        candidates = self._candidates(apex)

        sem = asyncio.Semaphore(int(self.config.get("dns_concurrency", 20)))

        async def probe(candidate: str) -> tuple[str, list[str]] | None:
            if scope is not None and not scope.is_in_scope(candidate):
                return None
            async with sem:
                ips = await resolve(candidate)
            return (candidate, ips) if ips else None

        ctx.log.info("subdomains.scan", apex=apex, candidates=len(candidates))
        results = await asyncio.gather(*(probe(c) for c in candidates))
        found = [r for r in results if r]

        findings: list[Finding] = []
        for name, ips in sorted(found):
            interest = name.split(".", 1)[0] in self.INTERESTING
            severity = Severity.LOW if interest else Severity.INFO
            finding = Finding(
                title=f"Subdomain discovered: {name}",
                module=self.name,
                target=apex,
                severity=severity,
                confidence=Confidence.CONFIRMED,
                category="subdomain",
                description=(
                    f"`{name}` resolves to {', '.join(ips)}. "
                    + ("The label suggests a sensitive function (admin/staging/CI)." if interest else "")
                ).strip(),
                impact="Each additional host expands the external attack surface.",
                remediation="Decommission unused hostnames and monitor DNS for shadow IT.",
                metadata={"subdomain": name, "addresses": ips, "interesting": interest},
                evidence=[
                    Evidence(kind="dns", summary=f"{name} -> {', '.join(ips)}")
                ],
            )
            findings.append(finding)
            ctx.shared.setdefault("subdomains", []).append(name)

        ctx.log.info("subdomains.done", apex=apex, found=len(findings))
        return findings
