"""Tests for the ecosystem tools: scope import, SARIF export, run comparison."""

import json

import compare_runs
import import_scope
import to_sarif


# -- import_scope ------------------------------------------------------------ #
def test_import_scope_from_plain_text():
    entries = import_scope.parse_plain("acme.com\n!billing.acme.com\n# comment\napi.acme.com\n")
    scope = import_scope.to_scope(entries)
    assert scope["in_scope"] == ["acme.com", "api.acme.com"]
    assert scope["out_of_scope"] == ["billing.acme.com"]


def test_import_scope_from_hackerone_json():
    payload = json.dumps([
        {"identifier": "*.acme.com", "asset_type": "WILDCARD", "eligible_for_submission": True},
        {"identifier": "billing.acme.com", "asset_type": "URL", "eligible_for_submission": False},
        {"identifier": "misc", "asset_type": "OTHER", "eligible_for_submission": True},
    ])
    scope = import_scope.to_scope(import_scope.parse_json(payload))
    assert "*.acme.com" in scope["in_scope"]
    assert "billing.acme.com" in scope["out_of_scope"]
    assert "misc" in scope["out_of_scope"]  # OTHER is not actionable


def test_import_scope_from_csv():
    csv_text = "identifier,asset_type,eligible_for_submission\nacme.com,DOMAIN,true\nx.acme.com,DOMAIN,false\n"
    scope = import_scope.to_scope(import_scope.parse_csv(csv_text))
    assert scope["in_scope"] == ["acme.com"]
    assert scope["out_of_scope"] == ["x.acme.com"]


def test_import_scope_writes_files(tmp_path):
    src = tmp_path / "scope.txt"
    src.write_text("acme.com\n")
    scope_out = tmp_path / "scope.json"
    eng_out = tmp_path / "engagement.json"
    rc = import_scope.main([str(src), "-o", str(scope_out), "--engagement", str(eng_out), "--name", "t"])
    assert rc == 0
    assert json.loads(scope_out.read_text())["in_scope"] == ["acme.com"]
    assert json.loads(eng_out.read_text())["name"] == "t"


# -- to_sarif ---------------------------------------------------------------- #
_RESULTS = {
    "engagement": {"name": "demo"},
    "risk": {"score": 40.1, "grade": "D"},
    "findings": [
        {
            "title": "SQL injection in q", "module": "sqli", "target": "app.example.com",
            "severity": "critical", "confidence": "confirmed", "category": "injection",
            "cwe": "CWE-89", "description": "injectable", "attck": ["T1190"], "cvss_score": 9.8,
            "references": ["https://owasp.org/"], "remediation": "parameterise",
        },
        {
            "title": "Missing header", "module": "http-headers", "target": "app.example.com",
            "severity": "low", "confidence": "firm", "category": "headers", "cwe": "CWE-693",
        },
    ],
}


def test_sarif_structure_and_levels():
    sarif = to_sarif.build_sarif(_RESULTS)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "VANTA"
    assert len(run["results"]) == 2
    levels = {r["level"] for r in run["results"]}
    assert "error" in levels and "note" in levels
    assert run["properties"]["riskGrade"] == "D"


def test_sarif_main_writes_file(tmp_path):
    results = tmp_path / "results.json"
    results.write_text(json.dumps(_RESULTS))
    out = tmp_path / "vanta.sarif"
    assert to_sarif.main([str(results), "-o", str(out)]) == 0
    assert json.loads(out.read_text())["runs"][0]["results"]


# -- compare_runs ------------------------------------------------------------ #
def _results(findings, score):
    return {"risk": {"score": score}, "findings": findings}


def test_compare_detects_fixed_new_and_persisting():
    old = _results([
        {"module": "sqli", "title": "A", "target": "h", "severity": "critical"},
        {"module": "xss", "title": "B", "target": "h", "severity": "high"},
    ], 60.0)
    new = _results([
        {"module": "xss", "title": "B", "target": "h", "severity": "high"},
        {"module": "ssrf", "title": "C", "target": "h", "severity": "high"},
    ], 35.0)

    diff = compare_runs.compare(old, new)
    assert [f["title"] for f in diff["fixed"]] == ["A"]
    assert [f["title"] for f in diff["new"]] == ["C"]
    assert [f["title"] for f in diff["persisting"]] == ["B"]
    assert "improved" in compare_runs.render(diff)


def test_compare_exit_code_signals_regression(tmp_path):
    old = _results([], 0.0)
    new = _results([{"module": "m", "title": "X", "target": "h", "severity": "high"}], 20.0)
    old_p, new_p = tmp_path / "o.json", tmp_path / "n.json"
    old_p.write_text(json.dumps(old))
    new_p.write_text(json.dumps(new))
    assert compare_runs.main([str(old_p), str(new_p)]) == 1  # new finding => non-zero

    same = tmp_path / "s.json"
    same.write_text(json.dumps(new))
    assert compare_runs.main([str(new_p), str(same)]) == 0
