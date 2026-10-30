"""HTTP security-header and cookie hygiene checks.

Checks the controls that actually stop whole bug classes in the browser:
CSP (XSS), HSTS (downgrade), X-Frame-Options/frame-ancestors (clickjacking),
X-Content-Type-Options (MIME sniffing), and cookie flags (session theft).
"""

from __future__ import annotations

from vanta.core.models import Confidence, Evidence, Finding, Severity
from vanta.core.registry import Module, RunContext, register


def _parse_cookies(resp) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    raw = resp.headers.get_all("set-cookie") if hasattr(resp.headers, "get_all") else None
    values = raw if raw else ([resp.headers["set-cookie"]] if "set-cookie" in resp.headers else [])
    for value in values:
        first = value.split(";", 1)[0]
        if "=" in first:
            name, val = first.split("=", 1)
            out.append((name.strip(), val.strip()))
    return out


@register
class SecurityHeaders(Module):
    name = "http-headers"
    category = "headers"
    description = "Audit HTTP security headers and cookie attributes"
    phase = 35

    REQUIRED = {
        "content-security-policy": (
            Severity.MEDIUM,
            "Missing Content-Security-Policy weakens defence-in-depth against XSS.",
            "Define a restrictive CSP; start with default-src 'self' and tune.",
        ),
        "strict-transport-security": (
            Severity.LOW,
            "Missing HSTS allows protocol downgrade and cookie hijacking on the first request.",
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        ),
        "x-content-type-options": (
            Severity.LOW,
            "Missing X-Content-Type-Options allows MIME-type sniffing.",
            "Add X-Content-Type-Options: nosniff.",
        ),
        "x-frame-options": (
            Severity.LOW,
            "Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors).",
            "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
        ),
        "referrer-policy": (
            Severity.INFO,
            "Missing Referrer-Policy may leak URLs to third parties.",
            "Add Referrer-Policy: strict-origin-when-cross-origin.",
        ),
        "permissions-policy": (
            Severity.INFO,
            "Missing Permissions-Policy leaves powerful browser features unrestricted.",
            "Add Permissions-Policy to disable unused features (camera, geolocation, ...).",
        ),
    }

    async def run(self, ctx: RunContext) -> list[Finding]:
        await ctx.fetch()
        resp = await ctx.http.get(ctx.base_url)
        if not resp.ok:
            return []
        host = ctx.target.host
        findings: list[Finding] = []
        headers = resp.headers

        missing = [
            (name, sev, impact, fix)
            for name, (sev, impact, fix) in self.REQUIRED.items()
            if name not in headers
        ]
        if missing:
            findings.append(
                Finding(
                    title=f"{len(missing)} missing security header(s) on {host}",
                    module=self.name,
                    target=host,
                    severity=max(m[1] for m in missing),
                    confidence=Confidence.CONFIRMED,
                    category="headers",
                    description="Missing headers: " + ", ".join(m[0] for m in missing) + ".",
                    impact="; ".join(m[2] for m in missing),
                    remediation=" ".join(m[3] for m in missing),
                    cwe="CWE-693",
                    metadata={"missing": [m[0] for m in missing]},
                    evidence=[
                        Evidence(kind="http", summary=f"Headers present: {', '.join(sorted(headers))}")
                    ],
                )
            )

        # Cookie hygiene.
        for name, _value in _parse_cookies(resp):
            raw = ",".join(
                v for v in (headers.get("set-cookie", ""),)
            ).lower()
            issues = []
            if "httponly" not in raw:
                issues.append("missing HttpOnly")
            if "secure" not in raw:
                issues.append("missing Secure")
            if "samesite" not in raw:
                issues.append("missing SameSite")
            if issues:
                findings.append(
                    Finding(
                        title=f"Cookie '{name}' lacks security attributes on {host}",
                        module=self.name,
                        target=host,
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        category="headers",
                        description=f"Cookie {name!r} is set without: {', '.join(issues)}.",
                        impact="Session cookies without flags are readable by scripts or sent over HTTP.",
                        remediation="Set HttpOnly, Secure and SameSite=Lax/Strict on session cookies.",
                        cwe="CWE-1004",
                        metadata={"cookie": name, "issues": issues},
                        evidence=[Evidence(kind="cookie", summary=f"{name}: {', '.join(issues)}")],
                    )
                )
        return findings
