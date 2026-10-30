"""The orchestration engine.

Responsibilities, in order:

1. Build the concrete target list from the engagement scope.
2. Enforce scope *before* any module runs against a host.
3. Run modules in kill-chain order with a shared, rate-limited HTTP client.
4. Capture findings, write the ops log, hash evidence.
5. Correlate everything into risk + attack paths for the report layer.

The engine owns no attack logic itself; that all lives in modules. This keeps
the trust boundary in one place and makes the framework testable: you can run
the engine with fake modules and assert on the orchestration alone.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from vanta.core import registry
from vanta.core.attck import techniques_for
from vanta.core.evidence import EvidenceStore
from vanta.core.graph import AttackGraph, AttackPath, build_graph, derive_paths
from vanta.core.http import HttpClient
from vanta.core.models import Engagement, Finding, ModuleResult, Target
from vanta.core.oplog import OpsLog
from vanta.core.ratelimit import HostLimiter
from vanta.core.registry import RunContext
from vanta.core.scope import Scope, ScopeViolation
from vanta.core.scoring import RiskProfile, aggregate_risk


@dataclass
class ScanReport:
    engagement: Engagement
    targets: list[Target] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    module_results: list[ModuleResult] = field(default_factory=list)
    risk: RiskProfile | None = None
    graphs: dict[str, AttackGraph] = field(default_factory=dict)
    paths: dict[str, list[AttackPath]] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    output_dir: str = ""

    @property
    def duration(self) -> float:
        return self.finished_at - self.started_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement": self.engagement.to_dict(),
            "targets": [t.to_dict() for t in self.targets],
            "risk": self.risk.to_dict() if self.risk else None,
            "findings": [f.to_dict() for f in self.findings],
            "modules": [
                {
                    "module": r.module,
                    "findings": len(r.findings),
                    "error": r.error,
                    "skipped": r.skipped,
                    "skip_reason": r.skip_reason,
                    "duration": round(r.duration, 3),
                }
                for r in self.module_results
            ],
            "attack_paths": {
                host: [p.describe() for p in paths] for host, paths in self.paths.items()
            },
            "duration": round(self.duration, 2),
        }


class Engine:
    def __init__(
        self,
        engagement: Engagement,
        scope: Scope,
        output_dir: str | Path = "engagements",
        active: bool = False,
        offline: bool = False,
        module_names: list[str] | None = None,
        categories: list[str] | None = None,
        rate_limit: float | None = None,
        concurrency: int = 10,
        timeout: float = 10.0,
        quiet: bool = False,
    ) -> None:
        self.engagement = engagement
        self.scope = scope
        self.active = active
        self.offline = offline
        self.timeout = timeout
        self.quiet = quiet

        meta = engagement.metadata or {}
        self.rate_limit = rate_limit or float(meta.get("rate_limit", 10.0))
        self.concurrency = int(meta.get("concurrency", concurrency))

        self.output_dir = Path(output_dir) / _slug(engagement.name)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.log = OpsLog(self.output_dir / "ops.jsonl", echo=not quiet)
        self.evidence = EvidenceStore(self.output_dir / "evidence")
        self.limiter = HostLimiter(
            global_rate=self.rate_limit,
            per_host_rate=max(self.rate_limit / 2, 1.0),
            max_concurrency=self.concurrency,
        )
        self.http = HttpClient(
            scope=scope, limiter=self.limiter, timeout=timeout
        )

        registry.discover()
        self.module_names = module_names or engagement.modules or None
        self.categories = categories

    # -- target construction ---------------------------------------------
    def build_targets(self, explicit: Iterable[str] | None = None) -> list[Target]:
        """Concrete, in-scope targets. Wildcards cannot be scanned directly."""
        hosts: list[str] = list(explicit or [])
        if not hosts:
            for entry in self.scope.in_scope:
                if entry.startswith("*.") or "/" in entry:
                    continue
                host = entry
                if "://" in host:
                    from urllib.parse import urlparse

                    host = urlparse(host).hostname or ""
                if host and host not in hosts:
                    hosts.append(host)

        targets: list[Target] = []
        meta = self.engagement.metadata or {}
        scheme = meta.get("scheme")
        port = meta.get("port")
        path = meta.get("path", "/")
        for host in hosts:
            if not self.scope.is_in_scope(host):
                self.log.warn("scope.reject", host=host)
                continue
            targets.append(
                Target(
                    host=host,
                    scheme=scheme or "https",
                    port=int(port) if port else None,
                    path=path,
                )
            )
        return targets

    # -- running ----------------------------------------------------------
    async def run(self, explicit_targets: Iterable[str] | None = None) -> ScanReport:
        targets = self.build_targets(explicit_targets)
        modules = registry.select(self.module_names, self.categories)

        self.log.info(
            "engine.start",
            engagement=self.engagement.name,
            targets=len(targets),
            modules=len(modules),
            active=self.active,
        )
        if not modules:
            self.log.warn("engine.no-modules")
        if not targets:
            self.log.warn("engine.no-targets")

        report = ScanReport(engagement=self.engagement, targets=targets, output_dir=str(self.output_dir))

        for target in targets:
            try:
                self.scope.assert_in_scope(target.host)
            except ScopeViolation as exc:  # defensive: should be unreachable
                self.log.error("scope.violation", detail=str(exc))
                continue
            await self._run_target(target, modules, report)

        report.finished_at = time.time()
        report.risk = aggregate_risk(report.findings)

        # Correlate per-host attack paths.
        for target in targets:
            host_findings = [f for f in report.findings if f.target == target.host]
            g = build_graph(target.host, host_findings)
            report.graphs[target.host] = g
            paths = derive_paths(g, host_findings)
            if paths:
                report.paths[target.host] = paths

        self._persist(report)
        self.log.info(
            "engine.done",
            findings=len(report.findings),
            risk=round(report.risk.score, 1),
            grade=report.risk.grade,
            duration=round(report.duration, 2),
        )
        return report

    async def _run_target(
        self, target: Target, modules: list[type], report: ScanReport
    ) -> None:
        self.log.info("target.start", host=target.host)
        ctx = RunContext(
            target=target,
            http=self.http,
            evidence=self.evidence,
            log=self.log,
            config=self.engagement.metadata or {},
            active=self.active,
            offline=self.offline,
        )

        for module_cls in modules:
            mod = module_cls(self.engagement.metadata or {})
            reason = mod.requires(ctx)
            if reason:
                report.module_results.append(
                    ModuleResult(module=mod.name, skipped=True, skip_reason=reason)
                )
                self.log.debug("module.skip", module=mod.name, host=target.host, reason=reason)
                continue

            start = time.monotonic()
            try:
                findings = await asyncio.wait_for(mod.run(ctx), timeout=self.timeout * 6)
                for f in findings:
                    f.module = f.module or mod.name
                    if not f.attck:
                        f.attck = techniques_for(f.category, mod.attck)
                result = ModuleResult(
                    module=mod.name,
                    findings=findings,
                    duration=time.monotonic() - start,
                )
                self.log.info(
                    "module.done",
                    module=mod.name,
                    host=target.host,
                    findings=len(findings),
                    ms=int(result.duration * 1000),
                )
            except Exception as exc:  # noqa: BLE001 - one module must not kill the run
                result = ModuleResult(
                    module=mod.name,
                    error=f"{type(exc).__name__}: {exc}",
                    duration=time.monotonic() - start,
                )
                self.log.error("module.error", module=mod.name, host=target.host, detail=str(exc))

            report.module_results.append(result)
            report.findings.extend(result.findings)

    # -- persistence ------------------------------------------------------
    def _persist(self, report: ScanReport) -> None:
        payload = report.to_dict()
        (self.output_dir / "results.json").write_text(
            json.dumps(payload, indent=2, default=str), encoding="utf-8"
        )
        for host, g in report.graphs.items():
            (self.output_dir / f"graph-{_slug(host)}.dot").write_text(
                g.to_dot(), encoding="utf-8"
            )


def _slug(text: str) -> str:
    keep = [c if c.isalnum() or c in "-_." else "-" for c in text.strip().lower()]
    return "".join(keep).strip("-") or "engagement"
