"""End-to-end engine test using a fake module (no network access required)."""

import asyncio
import json

from vanta.core.engine import Engine
from vanta.core.models import Engagement, Severity
from vanta.core.registry import Module, RunContext, register
from vanta.core.scope import Scope


@register
class _FakeModule(Module):
    name = "test-fake"
    category = "recon"
    description = "deterministic module for tests"
    phase = 1

    async def run(self, ctx: RunContext):
        from vanta.core.models import Confidence, Finding

        assert ctx.target.host.endswith("example.test")
        return [
            Finding(
                title="fake critical",
                module=self.name,
                target=ctx.target.host,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                category="injection",
            )
        ]


def test_engine_runs_module_and_writes_outputs(tmp_path):
    scope = Scope(in_scope=["app.example.test"])
    engagement = Engagement(name="unit-test", scope=scope.to_dict(), modules=["test-fake"])

    engine = Engine(
        engagement=engagement,
        scope=scope,
        output_dir=tmp_path,
        quiet=True,
    )
    report = asyncio.run(engine.run())

    assert len(report.targets) == 1
    assert len(report.findings) == 1
    assert report.risk is not None and report.risk.score > 0

    out = tmp_path / "unit-test"
    assert (out / "results.json").exists()
    assert (out / "ops.jsonl").exists()

    payload = json.loads((out / "results.json").read_text())
    assert payload["findings"][0]["title"] == "fake critical"


def test_engine_refuses_out_of_scope_targets(tmp_path):
    scope = Scope(in_scope=["in.example.test"])
    engagement = Engagement(name="scope-test", scope=scope.to_dict(), modules=["test-fake"])
    engine = Engine(engagement=engagement, scope=scope, output_dir=tmp_path, quiet=True)

    report = asyncio.run(engine.run(explicit_targets=["evil.example.com"]))
    assert report.targets == []
    assert report.findings == []


def test_engine_skips_active_modules_without_flag(tmp_path):
    from vanta.modules.recon.portscan import PortScan

    scope = Scope(in_scope=["app.example.test"])
    engagement = Engagement(name="active-test", scope=scope.to_dict(), modules=["portscan"])
    engine = Engine(engagement=engagement, scope=scope, output_dir=tmp_path, quiet=True, active=False)
    report = asyncio.run(engine.run())

    assert any(r.skipped for r in report.module_results)
    assert all(not r.findings for r in report.module_results)
