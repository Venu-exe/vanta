"""Technology fingerprinting and WAF detection from HTTP responses.

Fingerprinting is passive: it only looks at headers, cookies and a small set of
body markers from a single request. The result feeds later modules (e.g. a
WordPress version hint) and the report's asset inventory.
"""

from __future__ import annotations

from vanta.core.models import Confidence, Evidence, Finding, Severity
from vanta.core.registry import Module, RunContext, register

# header-name -> (product, marker)
_HEADER_SIGNATURES = {
    "x-powered-by": None,
    "x-aspnet-version": "ASP.NET",
    "x-drupal-cache": "Drupal",
    "x-generator": None,
    "server": None,
    "x-shopify-stage": "Shopify",
    "x-vercel-id": "Vercel",
}

_WAF_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "x-cdn": "CDN",
    "x-amz-cf-id": "AWS CloudFront",
    "x-azure-ref": "Azure Front Door",
}

_BODY_SIGNATURES = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "drupal.js": "Drupal",
    "/sites/default/files": "Drupal",
    "joomla": "Joomla",
    "__next_data__": "Next.js",
    "ng-version": "Angular",
    "data-reactroot": "React",
    "csrf-token": "Rails/Laravel-style CSRF",
}


@register
class TechDetect(Module):
    name = "techdetect"
    category = "tech-detect"
    description = "Fingerprint web technologies, servers and CDN/WAF from headers and body"
    phase = 30

    async def run(self, ctx: RunContext) -> list[Finding]:
        # Warm the base URL (auto-detects http vs https and the working port).
        await ctx.fetch()
        resp = await ctx.http.get(ctx.base_url)
        if not resp.ok:
            ctx.log.warn("techdetect.unreachable", url=ctx.target.url, error=resp.error)
            return []

        products: set[str] = set()
        for header, product in _HEADER_SIGNATURES.items():
            if header in resp.headers:
                products.add(product or f"{header}: {resp.headers[header]}")

        waf = [name for header, name in _WAF_SIGNATURES.items() if header in resp.headers]

        body = resp.text.lower()
        for marker, product in _BODY_SIGNATURES.items():
            if marker in body and product not in products:
                products.add(product)

        findings: list[Finding] = []
        technologies = {
            p.split(":", 1)[0].strip() for p in products
        } - {"server", "x-powered-by", "x-generator"}

        # Hand product/version pairs to the CVE module via shared state.
        ctx.shared.setdefault("technologies", [])
        for header in ("server", "x-powered-by", "x-aspnet-version"):
            value = resp.headers.get(header)
            if not value:
                continue
            product, _, version = value.partition("/")
            ctx.shared["technologies"].append(
                {"product": product.strip().lower(), "version": version.strip().split(" ")[0]}
            )

        findings.append(
            Finding(
                title=f"Technology fingerprint for {ctx.target.host}",
                module=self.name,
                target=ctx.target.host,
                severity=Severity.INFO,
                confidence=Confidence.FIRM,
                category="tech-detect",
                description=(
                    "Detected technologies: " + (", ".join(sorted(products)) or "none identified")
                    + (f". WAF/CDN: {', '.join(waf)}." if waf else ".")
                ),
                impact="Version disclosure helps an attacker target known-vulnerable components.",
                remediation="Suppress unnecessary version banners and keep components patched.",
                metadata={
                    "technologies": sorted(technologies),
                    "waf": waf,
                    "server": resp.headers.get("server", ""),
                },
                evidence=[
                    Evidence(
                        kind="http",
                        summary=f"GET {ctx.target.url} -> {resp.status}",
                        sha256=Evidence.hash_bytes(resp.body),
                    )
                ],
            )
        )

        # Missing WAF on an internet-facing app is worth a note but not a finding
        # by itself; only surface it when combined with something else. We keep it
        # as metadata to avoid noise.
        return findings
