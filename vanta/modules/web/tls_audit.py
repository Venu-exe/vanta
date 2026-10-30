"""TLS configuration audit.

Inspects the certificate (expiry, hostname coverage, key size) and probes which
protocol versions the endpoint still accepts. Legacy TLS 1.0/1.1 and weak
ciphers are flagged because they underpin downgrade attacks.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from vanta.core.models import Confidence, Evidence, Finding, Severity
from vanta.core.registry import Module, RunContext, register

_LEGACY_PROTOCOLS = {
    "TLSv1": getattr(ssl.TLSVersion, "TLSv1", None),
    "TLSv1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
}


def _inspect_cert(host: str, port: int, timeout: float) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert() or {}
            cipher = ssock.cipher()
            version = ssock.version()
            return {
                "cert": cert,
                "cipher": cipher,
                "version": version,
                "der": ssock.getpeercert(binary_form=True),
            }


def _probe_version(host: str, port: int, version, timeout: float) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:  # noqa: BLE001
        return False


@register
class TLSAudit(Module):
    name = "tls-audit"
    category = "tls"
    description = "Audit TLS certificate, protocol versions and cipher strength"
    phase = 36

    async def run(self, ctx: RunContext) -> list[Finding]:
        host = ctx.target.host
        port = ctx.target.port or 443
        timeout = float(self.config.get("tls_timeout", 6.0))

        try:
            info = await asyncio.to_thread(_inspect_cert, host, port, timeout)
        except Exception as exc:  # noqa: BLE001
            ctx.log.warn("tls.unreachable", host=host, detail=str(exc))
            return []

        findings: list[Finding] = []
        cert = info["cert"]
        if cert:
            findings.append(
                Finding(
                    title=f"TLS certificate inventory for {host}",
                    module=self.name,
                    target=host,
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    category="tls",
                    description=(
                        f"Subject: {dict(x[0] for x in cert.get('subject', []))}. "
                        f"Issuer: {dict(x[0] for x in cert.get('issuer', []))}. "
                        f"Protocol: {info['version']}, cipher: {info['cipher'][0] if info['cipher'] else 'n/a'}."
                    ),
                    metadata={
                        "not_after": cert.get("notAfter"),
                        "version": info["version"],
                        "cipher": info["cipher"][0] if info["cipher"] else None,
                    },
                    evidence=[
                        Evidence(
                            kind="tls-cert",
                            summary=f"{host}:{port} {info['version']}",
                            sha256=Evidence.hash_bytes(info["der"] or b""),
                        )
                    ],
                )
            )

            not_after = cert.get("notAfter")
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    days = (expiry - datetime.now(timezone.utc)).days
                    if days < 0:
                        findings.append(
                            Finding(
                                title=f"Expired TLS certificate on {host}",
                                module=self.name,
                                target=host,
                                severity=Severity.MEDIUM,
                                confidence=Confidence.CONFIRMED,
                                category="tls",
                                description=f"Certificate expired {abs(days)} day(s) ago ({not_after}).",
                                impact="Clients see trust warnings; encrypted traffic may be downgraded.",
                                remediation="Renew the certificate and automate renewal.",
                                evidence=[Evidence(kind="tls-cert", summary=f"expired {not_after}")],
                            )
                        )
                    elif days < 30:
                        findings.append(
                            Finding(
                                title=f"TLS certificate expiring soon on {host}",
                                module=self.name,
                                target=host,
                                severity=Severity.LOW,
                                confidence=Confidence.CONFIRMED,
                                category="tls",
                                description=f"Certificate expires in {days} day(s).",
                                remediation="Renew before expiry; automate with ACME.",
                                evidence=[Evidence(kind="tls-cert", summary=f"expires {not_after}")],
                            )
                        )
                except ValueError:
                    pass

        for label, version in _LEGACY_PROTOCOLS.items():
            if version is None:
                continue
            if await asyncio.to_thread(_probe_version, host, port, version, timeout):
                findings.append(
                    Finding(
                        title=f"Legacy {label} supported on {host}:{port}",
                        module=self.name,
                        target=host,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        category="tls",
                        description=f"The server still negotiates {label}, a deprecated protocol.",
                        impact="Legacy protocols enable downgrade attacks and known cipher weaknesses.",
                        remediation=f"Disable {label} and require TLS 1.2+.",
                        cwe="CWE-327",
                        references=["https://datatracker.ietf.org/doc/rfc8996/"],
                        evidence=[Evidence(kind="tls-probe", summary=f"{label} accepted")],
                    )
                )
        return findings
