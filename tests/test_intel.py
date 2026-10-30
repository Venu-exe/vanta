"""ATT&CK mapping, attack-graph traversal, and evidence custody tests."""

from vanta.core.attck import coverage_matrix, describe, techniques_for, tactic_for
from vanta.core.evidence import EvidenceStore
from vanta.core.graph import build_graph, derive_paths
from vanta.core.models import Confidence, Finding, Severity


def _finding(**kw):
    base = dict(title="t", module="m", target="example.com", severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED)
    base.update(kw)
    return Finding(**base)


def test_techniques_for_category_and_explicit_override():
    assert "T1190" in techniques_for("injection")
    assert techniques_for("injection", ["T1595"]) == ["T1595"]
    assert techniques_for("nonsense") == []


def test_tactic_lookup_and_describe():
    assert tactic_for("T1558.003") == "Credential Access"
    assert "Kerberoasting" in describe("T1558.003")


def test_coverage_matrix_groups_by_tactic():
    f = _finding(category="injection", attck=["T1190"])
    matrix = coverage_matrix([f])
    assert "Initial Access" in matrix
    assert matrix["Initial Access"] == ["T1190"]


def test_graph_builds_paths_from_host_to_findings():
    f1 = _finding(title="open port", category="service", severity=Severity.LOW, metadata={"port": 3306})
    f2 = _finding(title="weak creds", category="auth", severity=Severity.CRITICAL, metadata={"port": 3306})
    g = build_graph("example.com", [f1, f2])
    paths = derive_paths(g, [f1, f2])
    assert paths
    assert "example.com" in paths[0].nodes[0]


def test_graph_chains_leads_to_edges():
    a = _finding(title="exposed admin", severity=Severity.MEDIUM)
    b = _finding(title="rce", severity=Severity.CRITICAL)
    a.leads_to = b.id
    g = build_graph("h", [a, b])
    assert g.shortest_path(f"finding:{a.id}", f"finding:{b.id}") == [f"finding:{a.id}", f"finding:{b.id}"]


def test_graph_dot_export():
    f = _finding(category="service", metadata={"port": 443})
    dot = build_graph("h", [f]).to_dot()
    assert dot.startswith("digraph")
    assert "->" in dot


def test_evidence_store_hash_and_verify(tmp_path):
    store = EvidenceStore(tmp_path)
    ev = store.store("http", "test artefact", b"hello world")
    assert ev.sha256
    assert (tmp_path / ev.path).exists()

    ok, problems = store.verify()
    assert ok and problems == []

    # Tamper with the artefact and confirm detection.
    (tmp_path / ev.path).write_bytes(b"tampered")
    ok, problems = store.verify()
    assert not ok
    assert problems
