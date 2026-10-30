"""VANTA command-line interface.

Subcommands mirror how an engagement actually flows:

    vanta modules                 # see what the framework can do
    vanta scope validate ...      # check a host against a scope before you touch it
    vanta scan ...                # run modules and produce a report
    vanta report ...              # re-render a saved results.json
    vanta evidence verify ...     # prove the chain of custody still holds

Uses argparse from the standard library; ``rich`` is used opportunistically for
prettier tables but the tool is fully functional without it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from vanta import __version__
from vanta.core import registry
from vanta.core.config import ConfigError, load_engagement, load_scope, DEFAULT_ENGAGEMENT
from vanta.core.engine import Engine, ScanReport
from vanta.core.evidence import EvidenceStore
from vanta.core.models import Engagement, Finding, Severity
from vanta.core.scope import Scope
from vanta.report import render_html, render_markdown

# --------------------------------------------------------------------------- #
# Optional rich output, with a graceful fallback.
try:  # pragma: no cover - trivial import shim
    from rich.console import Console
    from rich.table import Table

    _RICH = True
except Exception:  # noqa: BLE001
    _RICH = False


def _print_banner() -> None:
    print(f"VANTA v{__version__} — red-team-minded pentest & bug bounty framework")


# --------------------------------------------------------------------------- #
def cmd_modules(args: argparse.Namespace) -> int:
    registry.discover()
    mods = registry.all_modules()
    if args.json:
        print(json.dumps(
            {
                name: {
                    "category": cls.category,
                    "active": cls.active,
                    "phase": cls.phase,
                    "description": cls.description,
                    "attck": list(cls.attck),
                }
                for name, cls in sorted(mods.items())
            },
            indent=2,
        ))
        return 0

    by_cat = registry.by_category()
    print(f"\n{len(mods)} modules available:\n")
    for cat, names in by_cat.items():
        print(f"  [{cat}]")
        for name in names:
            cls = mods[name]
            flag = " (active — needs --allow-active)" if cls.active else ""
            print(f"    {name:<16} {cls.description}{flag}")
        print()
    return 0


def cmd_scope_validate(args: argparse.Namespace) -> int:
    scope = load_scope(args.scope) if args.scope else Scope.from_iterable(args.hosts)
    rc = 0
    for host in args.hosts:
        verdict = scope.explain(host)
        in_scope = scope.is_in_scope(host)
        rc = rc or (0 if in_scope else 2)
        print(f"  {'ALLOW' if in_scope else 'DENY ':4}  {verdict}")
    return rc


def _build_engine(args: argparse.Namespace) -> Engine:
    if args.target:
        scope = load_scope(args.scope) if args.scope else Scope.from_iterable(args.target, label="cli")
        engagement = Engagement(
            name=args.name or "cli-engagement",
            scope=scope.to_dict(),
            modules=args.modules or [],
            metadata={},
        )
    else:
        if not args.engagement:
            raise ConfigError("provide --engagement or at least one --target")
        engagement, scope = load_engagement(args.engagement)

    # CLI metadata is merged *over* the engagement file so flags win without
    # discarding the file's other settings.
    if args.metadata:
        engagement.metadata.update(json.loads(args.metadata))
    if args.modules:
        engagement.modules = args.modules
    if args.rate:
        engagement.metadata["rate_limit"] = args.rate

    return Engine(
        engagement=engagement,
        scope=scope,
        output_dir=args.output,
        active=args.allow_active,
        offline=args.offline,
        module_names=args.modules or None,
        categories=args.category or None,
        rate_limit=args.rate,
        concurrency=args.concurrency,
        timeout=args.timeout,
        quiet=args.quiet,
    )


def cmd_scan(args: argparse.Namespace) -> int:
    _print_banner()
    try:
        engine = _build_engine(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not args.allow_active:
        print("note: active modules are disabled (pass --allow-active for intrusive checks)\n")

    report = asyncio.run(engine.run(explicit_targets=args.target))

    md = render_markdown(report)
    md_path = Path(report.output_dir) / "report.md"
    md_path.write_text(md, encoding="utf-8")

    if not args.no_html:
        html_path = Path(report.output_dir) / "report.html"
        html_path.write_text(render_html(report), encoding="utf-8")
    else:
        html_path = None

    _summarise(report, md_path, html_path)
    return 0


def _summarise(report: ScanReport, md_path: Path, html_path: Path | None) -> None:
    risk = report.risk
    print("\n" + "=" * 62)
    print(f"  Engagement : {report.engagement.name}")
    print(f"  Targets    : {len(report.targets)}")
    print(f"  Findings   : {len(report.findings)}")
    if risk:
        print(f"  Risk score : {risk.score:.1f}/100  (grade {risk.grade})")
        counts = ", ".join(
            f"{s.value}:{risk.severity_counts[s.value]}"
            for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        )
        print(f"  Severity   : {counts}")
    if report.paths:
        print("  Attack paths:")
        for host, paths in report.paths.items():
            for p in paths[:2]:
                print(f"    - {p.describe()}")
    print("=" * 62)
    print(f"  Markdown   : {md_path}")
    if html_path:
        print(f"  HTML       : {html_path}")
    print(f"  Results    : {Path(report.output_dir) / 'results.json'}")
    print(f"  Ops log    : {Path(report.output_dir) / 'ops.jsonl'}")


def cmd_report(args: argparse.Namespace) -> int:
    results = Path(args.results)
    if not results.exists():
        print(f"error: {results} not found", file=sys.stderr)
        return 1
    data = json.loads(results.read_text(encoding="utf-8"))

    # Rebuild a minimal report object from the saved JSON; the renderers only
    # need the same duck-typed shape.
    out_dir = results.parent
    report = _report_from_dict(data, out_dir)
    md_path = out_dir / "report.md"
    md_path.write_text(render_markdown(report), encoding="utf-8")
    html_path = out_dir / "report.html"
    html_path.write_text(render_html(report), encoding="utf-8")
    print(f"re-rendered:\n  {md_path}\n  {html_path}")
    return 0


def _report_from_dict(data: dict, out_dir: Path):
    """Rehydrate a ScanReport-like object from results.json for re-rendering."""
    from types import SimpleNamespace

    from vanta.core.models import Confidence, Evidence, Target
    from vanta.core.scoring import RiskProfile

    def _finding(d: dict) -> Finding:
        return Finding(
            title=d["title"],
            module=d["module"],
            target=d["target"],
            severity=Severity(d["severity"]),
            confidence=Confidence(d["confidence"]),
            description=d.get("description", ""),
            impact=d.get("impact", ""),
            remediation=d.get("remediation", ""),
            category=d.get("category", "general"),
            cwe=d.get("cwe"),
            owasp=d.get("owasp"),
            cvss_vector=d.get("cvss_vector"),
            cvss_score=d.get("cvss_score"),
            attck=d.get("attck", []),
            references=d.get("references", []),
            evidence=[Evidence(**{k: ev[k] for k in ("kind", "summary", "sha256", "path") if k in ev}) for ev in d.get("evidence", [])],
            metadata=d.get("metadata", {}),
            id=d.get("id", ""),
            discovered_at=d.get("discovered_at", 0.0),
        )

    findings = [_finding(d) for d in data.get("findings", [])]
    risk_data = data.get("risk") or {}
    risk = RiskProfile(
        score=risk_data.get("score", 0.0),
        grade=risk_data.get("grade", "A"),
        severity_counts=risk_data.get("severity_counts", {}),
        confidence_counts=risk_data.get("confidence_counts", {}),
        top_findings=risk_data.get("top_findings", []),
    ) if risk_data else None

    eng = SimpleNamespace(**{**data.get("engagement", {}), "to_dict": lambda: data.get("engagement", {})})
    targets = [Target(**{k: t[k] for k in ("host", "scheme", "port", "path") if k in t}) for t in data.get("targets", [])]

    paths = {}
    for host, descs in (data.get("attack_paths") or {}).items():
        paths[host] = [SimpleNamespace(describe=lambda d=d: d, risk=0.0) for d in descs]

    module_results = [
        SimpleNamespace(
            module=m["module"], findings=[None] * m.get("findings", 0),
            error=m.get("error"), skipped=m.get("skipped", False),
            skip_reason=m.get("skip_reason"), duration=m.get("duration", 0.0),
        )
        for m in data.get("modules", [])
    ]

    return SimpleNamespace(
        engagement=eng, targets=targets, findings=findings, module_results=module_results,
        risk=risk, graphs={}, paths=paths, started_at=0.0,
        finished_at=0.0, duration=data.get("duration", 0.0), output_dir=str(out_dir),
    )


def cmd_evidence_verify(args: argparse.Namespace) -> int:
    store = EvidenceStore(args.directory)
    ok, problems = store.verify()
    if ok:
        print(f"  chain of custody intact ({store.manifest_path})")
        return 0
    print("  integrity problems detected:")
    for p in problems:
        print(f"    - {p}")
    return 1


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"error: {path} exists (use --force)", file=sys.stderr)
        return 1
    path.write_text(json.dumps(DEFAULT_ENGAGEMENT, indent=2), encoding="utf-8")
    print(f"wrote engagement template: {path}")
    return 0


# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vanta",
        description="VANTA — red-team-minded penetration testing and bug bounty framework",
        epilog="Always confirm you are authorised before scanning anything.",
    )
    parser.add_argument("--version", action="version", version=f"vanta {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_mods = sub.add_parser("modules", help="list available modules")
    p_mods.add_argument("--json", action="store_true", help="machine-readable output")
    p_mods.set_defaults(func=cmd_modules)

    p_scope = sub.add_parser("scope", help="scope utilities")
    scope_sub = p_scope.add_subparsers(dest="scope_command", required=True)
    p_sv = scope_sub.add_parser("validate", help="check hosts against a scope")
    p_sv.add_argument("--scope", help="scope JSON/YAML file")
    p_sv.add_argument("hosts", nargs="+", help="hosts to test")
    p_sv.set_defaults(func=cmd_scope_validate)

    p_scan = sub.add_parser("scan", help="run modules against an engagement")
    p_scan.add_argument("--engagement", "-e", help="engagement JSON/YAML file")
    p_scan.add_argument("--scope", help="override scope file")
    p_scan.add_argument("--target", "-t", action="append", help="target host (repeatable)")
    p_scan.add_argument("--name", help="engagement name when using --target")
    p_scan.add_argument("--modules", "-m", nargs="*", help="modules to run (default: engagement list)")
    p_scan.add_argument("--category", "-c", action="append", help="run a whole category")
    p_scan.add_argument("--allow-active", action="store_true", help="enable intrusive modules")
    p_scan.add_argument("--offline", action="store_true", help="no external network calls")
    p_scan.add_argument("--rate", type=float, help="global requests/second")
    p_scan.add_argument("--concurrency", type=int, default=10)
    p_scan.add_argument("--timeout", type=float, default=10.0)
    p_scan.add_argument("--output", "-o", default="engagements")
    p_scan.add_argument("--metadata", help="JSON object merged into engagement metadata")
    p_scan.add_argument("--no-html", action="store_true", help="skip the HTML report")
    p_scan.add_argument("--quiet", "-q", action="store_true", help="suppress per-event logging")
    p_scan.set_defaults(func=cmd_scan)

    p_report = sub.add_parser("report", help="re-render a saved results.json")
    p_report.add_argument("results", help="path to results.json")
    p_report.set_defaults(func=cmd_report)

    p_ev = sub.add_parser("evidence", help="evidence utilities")
    ev_sub = p_ev.add_subparsers(dest="evidence_command", required=True)
    p_evv = ev_sub.add_parser("verify", help="verify the chain of custody")
    p_evv.add_argument("directory", help="engagement output directory")
    p_evv.set_defaults(func=cmd_evidence_verify)

    p_init = sub.add_parser("init", help="write an engagement template")
    p_init.add_argument("path", nargs="?", default="engagement.json")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
