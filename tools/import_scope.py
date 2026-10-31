#!/usr/bin/env python3
"""Import a bug-bounty programme scope into a VANTA scope (and engagement) file.

Supported inputs:

* **HackerOne-style JSON** — a list of objects, or ``{"scopes": [...]}``, with
  ``identifier`` / ``asset_type`` and an optional ``eligible_for_submission``.
* **CSV** with a header row containing ``identifier`` and (optionally)
  ``asset_type`` and ``eligible_for_submission``.
* **Plain text** — one entry per line, ``#`` comments, and a leading ``!`` to
  mark an exclusion.

Output is a VANTA scope document (``in_scope`` / ``out_of_scope``), and
optionally a full engagement file you can hand straight to ``vanta scan``.

Examples
--------
    python3 tools/import_scope.py hackerone.json -o scope.acme.json
    python3 tools/import_scope.py scope.csv -o scope.json \
        --engagement engagement.json --name acme-bounty --client "Acme Corp"
    printf 'acme.com\\n!billing.acme.com\\n' | python3 tools/import_scope.py - -o scope.json
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path

EXCLUDED_ASSET_TYPES = {"OTHER"}  # asset types we cannot act on directly


def _load_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def parse_json(text: str) -> list[tuple[str, bool]]:
    data = json.loads(text)
    if isinstance(data, dict):
        data = data.get("scopes") or data.get("data") or []
    entries: list[tuple[str, bool]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        identifier = item.get("identifier") or item.get("asset") or item.get("host")
        if not identifier:
            continue
        asset_type = str(item.get("asset_type", "")).upper()
        eligible = item.get("eligible_for_submission", True)
        if asset_type in EXCLUDED_ASSET_TYPES:
            eligible = False
        entries.append((str(identifier).strip(), bool(eligible)))
    return entries


def parse_csv(text: str) -> list[tuple[str, bool]]:
    reader = csv.DictReader(io.StringIO(text))
    entries: list[tuple[str, bool]] = []
    for row in reader:
        identifier = (row.get("identifier") or row.get("asset") or "").strip()
        if not identifier:
            continue
        eligible_raw = str(row.get("eligible_for_submission", "true")).strip().lower()
        eligible = eligible_raw not in ("false", "0", "no", "out_of_scope")
        entries.append((identifier, eligible))
    return entries


def parse_plain(text: str) -> list[tuple[str, bool]]:
    entries: list[tuple[str, bool]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            entries.append((line[1:].strip(), False))
        else:
            entries.append((line, True))
    return entries


def parse_any(path: str) -> list[tuple[str, bool]]:
    text = _load_text(path)
    suffix = Path(path).suffix.lower() if path != "-" else ""
    stripped = text.lstrip()
    if suffix == ".json" or stripped.startswith(("{", "[")):
        return parse_json(text)
    if suffix == ".csv" or ("," in text.splitlines()[0] if text.splitlines() else False):
        try:
            return parse_csv(text)
        except Exception:  # noqa: BLE001 - fall back to plain parsing
            pass
    return parse_plain(text)


def to_scope(entries: list[tuple[str, bool]]) -> dict:
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    for identifier, eligible in entries:
        (in_scope if eligible else out_of_scope).append(identifier)
    return {
        "label": "imported programme scope",
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
    }


def build_engagement(scope: dict, name: str, client: str, auth: str, modules: list[str]) -> dict:
    return {
        "name": name,
        "client": client,
        "authorisation_reference": auth,
        "scope": scope,
        "modules": modules,
        "metadata": {"rate_limit": 5, "concurrency": 8},
    }


DEFAULT_MODULES = [
    "subdomains", "portscan", "techdetect", "http-headers",
    "tls-audit", "crawler", "sqli", "xss", "ssrf", "cve-correlate",
]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="programme scope file, or '-' for stdin")
    parser.add_argument("-o", "--output", default="scope.json", help="scope output path")
    parser.add_argument("--engagement", help="also write an engagement file here")
    parser.add_argument("--name", default="imported-engagement")
    parser.add_argument("--client", default="")
    parser.add_argument("--authorisation", default="", help="authorisation reference / policy URL")
    parser.add_argument("--modules", nargs="*", default=DEFAULT_MODULES)
    args = parser.parse_args(argv)

    entries = parse_any(args.input)
    if not entries:
        print("error: no scope entries parsed", file=sys.stderr)
        return 1

    scope = to_scope(entries)
    Path(args.output).write_text(json.dumps(scope, indent=2) + "\n", encoding="utf-8")
    print(f"wrote scope: {args.output} ({len(scope['in_scope'])} in scope, "
          f"{len(scope['out_of_scope'])} excluded)")

    if args.engagement:
        eng = build_engagement(scope, args.name, args.client, args.authorisation, args.modules)
        Path(args.engagement).write_text(json.dumps(eng, indent=2) + "\n", encoding="utf-8")
        print(f"wrote engagement: {args.engagement}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
