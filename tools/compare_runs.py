#!/usr/bin/env python3
"""Diff two VANTA runs to show remediation progress over time.

    python3 tools/compare_runs.py engagements/acme/run-jan.json engagements/acme/run-feb.json

Findings are matched on (module, title, target) — stable across runs as long as
you have not renamed modules.

Exit code is 1 when *new* findings appeared (handy as a CI gate).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _key(finding: dict) -> tuple:
    return (finding.get("module", ""), finding.get("title", ""), finding.get("target", ""))


def _index(results: dict) -> dict[tuple, dict]:
    return {_key(f): f for f in results.get("findings", [])}


def _severity_rank(finding: dict) -> int:
    return _SEV_ORDER.index(finding.get("severity", "info"))


def compare(old: dict, new: dict) -> dict:
    old_index, new_index = _index(old), _index(new)
    old_keys, new_keys = set(old_index), set(new_index)

    fixed = sorted(old_keys - new_keys, key=lambda k: _severity_rank(old_index[k]), reverse=True)
    introduced = sorted(new_keys - old_keys, key=lambda k: _severity_rank(new_index[k]), reverse=True)
    persisting = sorted(old_keys & new_keys, key=lambda k: _severity_rank(new_index[k]), reverse=True)

    return {
        "fixed": [old_index[k] for k in fixed],
        "new": [new_index[k] for k in introduced],
        "persisting": [new_index[k] for k in persisting],
        "old_score": (old.get("risk") or {}).get("score", 0.0),
        "new_score": (new.get("risk") or {}).get("score", 0.0),
    }


def render(diff: dict) -> str:
    lines: list[str] = []
    delta = diff["new_score"] - diff["old_score"]
    arrow = "▼ improved" if delta < 0 else ("▲ regressed" if delta > 0 else "＝ unchanged")
    lines.append(f"Risk score: {diff['old_score']:.1f} -> {diff['new_score']:.1f}  ({arrow})")
    lines.append("")

    for label, items, mark in (
        ("FIXED", diff["fixed"], "✓"),
        ("NEW", diff["new"], "✗"),
        ("STILL OPEN", diff["persisting"], "·"),
    ):
        lines.append(f"{label} ({len(items)})")
        for f in items:
            lines.append(f"  {mark} [{f.get('severity','?'):>8}] {f.get('module','?'):<14} {f.get('title','')} ({f.get('target','')})")
        lines.append("")
    return "\n".join(lines).rstrip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("old", help="earlier results.json")
    parser.add_argument("new", help="later results.json")
    parser.add_argument("--json", action="store_true", help="emit the diff as JSON")
    args = parser.parse_args(argv)

    old = json.loads(Path(args.old).read_text(encoding="utf-8"))
    new = json.loads(Path(args.new).read_text(encoding="utf-8"))
    diff = compare(old, new)

    if args.json:
        print(json.dumps(diff, indent=2, default=str))
    else:
        print(render(diff))

    return 1 if diff["new"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
