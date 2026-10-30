"""Asynchronous TCP connect port scanner with light banner grabbing.

Connect() scanning needs no privileges, tolerates lossy networks, and is the
right default for an authorised assessment. Full-range SYN scanning is out of
scope for a portable Python tool, so we scan the curated common-port set plus
anything the engagement file adds.
"""

from __future__ import annotations

import asyncio

from vanta.core.models import Confidence, Evidence, Finding, Severity
from vanta.core.registry import Module, RunContext, register
from vanta.modules.recon._util import load_lines, resolve

_RISKY_PORTS = {
    21: "FTP",
    23: "Telnet (cleartext)",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    2375: "Docker daemon (unencrypted)",
}


@register
class PortScan(Module):
    name = "portscan"
    category = "portscan"
    description = "Async TCP connect scan of common ports with banner grabbing"
    active = True
    phase = 20

    async def _probe(self, ip: str, port: int, timeout: float) -> tuple[int, bytes] | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
        except (OSError, asyncio.TimeoutError):
            return None

        banner = b""
        try:
            # Many services (SSH, SMTP, FTP) greet immediately.
            banner = await asyncio.wait_for(reader.read(256), timeout=1.5)
        except (asyncio.TimeoutError, OSError):
            banner = b""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        return port, banner

    async def run(self, ctx: RunContext) -> list[Finding]:
        host = ctx.target.host
        ports = [int(p) for p in self.config.get("ports", [])] or [
            int(p) for p in load_lines("common-ports.txt")
            if p.isdigit()
        ]
        timeout = float(self.config.get("port_timeout", 2.0))

        ips = await resolve(host)
        if not ips:
            return []
        ip = ips[0]
        ctx.log.info("portscan.scan", host=host, ip=ip, ports=len(ports))

        sem = asyncio.Semaphore(int(self.config.get("port_concurrency", 100)))

        async def bounded(port: int):
            async with sem:
                return await self._probe(ip, port, timeout)

        results = await asyncio.gather(*(bounded(p) for p in ports))
        open_ports = [r for r in results if r]

        findings: list[Finding] = []
        if not open_ports:
            return findings

        summary = ", ".join(str(p) for p, _ in sorted(open_ports))
        findings.append(
            Finding(
                title=f"{len(open_ports)} open TCP port(s) on {host}",
                module=self.name,
                target=host,
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                category="service",
                description=f"Reachable TCP ports: {summary}.",
                impact="Open services expand the attack surface and may expose management planes.",
                remediation="Restrict exposure with firewall rules and remove unused services.",
                metadata={"ports": [p for p, _ in open_ports], "port": open_ports[0][0]},
                evidence=[Evidence(kind="portscan", summary=f"open: {summary}")],
            )
        )

        for port, banner in sorted(open_ports):
            banner_text = banner.decode("utf-8", errors="replace").strip()
            risky = port in _RISKY_PORTS
            sev = Severity.MEDIUM if port in (2375, 6379, 27017, 9200, 11211) else (
                Severity.LOW if risky else Severity.INFO
            )
            findings.append(
                Finding(
                    title=f"Exposed service on {host}:{port}"
                    + (f" ({_RISKY_PORTS[port]})" if risky else ""),
                    module=self.name,
                    target=host,
                    severity=sev,
                    confidence=Confidence.CONFIRMED,
                    category="service",
                    description=(
                        f"Port {port} is open"
                        + (f" — {_RISKY_PORTS[port]}" if risky else "")
                        + (f". Banner: {banner_text!r}" if banner_text else ".")
                    ),
                    impact=(
                        "Database/cache/container ports exposed to the internet are frequently "
                        "unauthenticated and lead directly to data compromise."
                        if port in (2375, 6379, 27017, 9200, 11211)
                        else "Each open port is an entry point that must be justified."
                    ),
                    remediation="Bind services to localhost or place them behind an authenticated gateway.",
                    metadata={"port": port, "banner": banner_text},
                    evidence=[Evidence(kind="banner", summary=f"{port}: {banner_text or '(no banner)'}")],
                    cwe="CWE-284",
                )
            )
        return findings
