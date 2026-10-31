#!/usr/bin/env python3
"""Convert a VANTA ``results.json`` into SARIF 2.1.0.

SARIF is what GitHub Code Scanning, Azure DevOps and most CI dashboards consume,
so this lets VANTA findings appear as annotations on a pull request.

    python3 tools/to_sarif.py engagements/acme/results.json -o vanta.sarif
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def finding_to_rule(finding: dict) -> dict:
    return {
        "id": finding.get("cwe") or finding.get("category") or finding.get("module", "vanta"),
        "name": finding.get("title", "finding"),
        "shortDescription": {"text": finding.get("title", "")},
        "fullDescription": {"text": finding.get("description") or finding.get("title", "")},
        "helpUri": (finding.get("references") or ["https://github.com/Venu-exe/vanta"])[0],
        "properties": {
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "attck": finding.get("attck", []),
        },
    }


def finding_to_result(finding: dict, rule_id: str) -> dict:
    location_uri = f"https://{finding.get('target', 'unknown')}"
    result = {
        "ruleId": rule_id,
        "level": _SEVERITY_TO_LEVEL.get(finding.get("severity", "info"), "note"),
        "message": {
            "text": f"{finding.get('title', '')} — {finding.get('description', '')}".strip(" —")
        },
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": location_uri}}}
        ],
        "properties": {
            "module": finding.get("module"),
            "severity": finding.get("severity"),
            "cvss_score": finding.get("cvss_score"),
            "remediation": finding.get("remediation"),
        },
    }
    return result


def build_sarif(results: dict) -> dict:
    findings = results.get("findings", [])
    rules: dict[str, dict] = {}
    sarif_results: list[dict] = []

    for finding in findings:
        rule = finding_to_rule(finding)
        rules.setdefault(rule["id"], rule)
        sarif_results.append(finding_to_result(finding, rule["id"]))

    risk = results.get("risk") or {}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VANTA",
                        "informationUri": "https://github.com/Venu-exe/vanta",
                        "version": "0.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
                "properties": {
                    "engagement": (results.get("engagement") or {}).get("name"),
                    "riskScore": risk.get("score"),
                    "riskGrade": risk.get("grade"),
                },
            }
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results", help="path to a VANTA results.json")
    parser.add_argument("-o", "--output", default="vanta.sarif")
    args = parser.parse_args(argv)

    data = json.loads(Path(args.results).read_text(encoding="utf-8"))
    sarif = build_sarif(data)
    Path(args.output).write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.output}: {len(sarif['runs'][0]['results'])} result(s), "
          f"{len(sarif['runs'][0]['tool']['driver']['rules'])} rule(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
