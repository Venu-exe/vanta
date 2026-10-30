"""Attack-path graph.

A flat findings list tells you *what* is broken. A graph tells you *how far*
an attacker gets. VANTA builds a lightweight directed graph whose nodes are
assets (hosts, ports, services) and whose edges are findings, then derives:

* entry points      - everything reachable from the internet edge
* attack paths      - an ordered chain from an entry point to a high-value node
* the "crown jewel" - the deepest, most severe node an attacker can reach

No third-party graph library: the traversal is a plain BFS so the algorithm is
readable and defensible in a viva.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterable

from vanta.core.models import Finding, Severity


@dataclass
class GraphNode:
    id: str
    label: str
    kind: str  # host | port | service | finding
    severity: Severity | None = None


@dataclass
class AttackPath:
    nodes: list[str]
    findings: list[Finding]
    risk: float

    def describe(self) -> str:
        return " → ".join(self.nodes)


@dataclass
class AttackGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: dict[str, list[str]] = field(default_factory=dict)

    def add_node(self, node: GraphNode) -> None:
        self.nodes.setdefault(node.id, node)
        self.edges.setdefault(node.id, [])

    def add_edge(self, src: str, dst: str) -> None:
        self.edges.setdefault(src, [])
        if dst not in self.edges[src]:
            self.edges[src].append(dst)

    def shortest_path(self, src: str, dst: str) -> list[str] | None:
        if src not in self.nodes or dst not in self.nodes:
            return None
        prev: dict[str, str] = {src: src}
        q: deque[str] = deque([src])
        while q:
            cur = q.popleft()
            if cur == dst:
                break
            for nxt in self.edges.get(cur, []):
                if nxt not in prev:
                    prev[nxt] = cur
                    q.append(nxt)
        if dst not in prev:
            return None
        path = [dst]
        while path[-1] != src:
            path.append(prev[path[-1]])
        return list(reversed(path))

    def reachable(self, src: str) -> list[str]:
        seen = {src}
        q: deque[str] = deque([src])
        while q:
            cur = q.popleft()
            for nxt in self.edges.get(cur, []):
                if nxt not in seen:
                    seen.add(nxt)
                    q.append(nxt)
        return sorted(seen)

    def to_dot(self) -> str:
        """Graphviz DOT export for the report's architecture diagram."""
        lines = ["digraph vanta {", '  rankdir=LR; node [shape=box, style=rounded];']
        for nid, node in self.nodes.items():
            colour = {
                Severity.CRITICAL: "firebrick",
                Severity.HIGH: "orangered",
                Severity.MEDIUM: "goldenrod",
                Severity.LOW: "steelblue",
            }.get(node.severity, "gray70")
            lines.append(
                f'  "{nid}" [label="{node.label}", color="{colour}"];'
            )
        for src, dsts in self.edges.items():
            for dst in dsts:
                lines.append(f'  "{src}" -> "{dst}";')
        lines.append("}")
        return "\n".join(lines)


def build_graph(host: str, findings: Iterable[Finding]) -> AttackGraph:
    """Assemble the graph for a single host's findings.

    Structure: ``host`` -> ``host:port`` -> ``service`` -> finding nodes.
    Findings with ``leads_to`` metadata chain to one another, modelling an
    escalation route (e.g. exposed admin panel -> default creds -> RCE).
    """
    g = AttackGraph()
    root = f"host:{host}"
    g.add_node(GraphNode(root, host, "host"))

    by_id = {f.id: f for f in findings}

    for f in findings:
        port = f.metadata.get("port")
        node_kind = "service" if f.category in ("service", "tech-detect") else "finding"
        parent = root

        if port:
            port_id = f"{host}:{port}"
            g.add_node(GraphNode(port_id, f"{host}:{port}", "port"))
            g.add_edge(root, port_id)
            parent = port_id

        fid = f"finding:{f.id}"
        g.add_node(GraphNode(fid, f.title, node_kind, f.severity))
        g.add_edge(parent, fid)

        if f.leads_to and f.leads_to in by_id:
            target_node = f"finding:{f.leads_to}"
            g.add_edge(fid, target_node)

    return g


def derive_paths(g: AttackGraph, findings: list[Finding], limit: int = 5) -> list[AttackPath]:
    """Rank the most dangerous reachable chains."""
    by_node = {f"finding:{f.id}": f for f in findings}
    root = next((n for n, node in g.nodes.items() if node.kind == "host"), None)
    if not root:
        return []

    paths: list[AttackPath] = []
    for nid, node in g.nodes.items():
        if node.kind == "host":
            continue
        f = by_node.get(nid)
        if f is None or f.severity.rank < Severity.MEDIUM.rank:
            continue
        chain = g.shortest_path(root, nid)
        if not chain:
            continue
        chain_findings = [by_node[n] for n in chain if n in by_node]
        risk = sum(x.cvss_score or x.severity.rank * 2 for x in chain_findings)
        paths.append(AttackPath(nodes=[g.nodes[n].label for n in chain], findings=chain_findings, risk=risk))

    paths.sort(key=lambda p: p.risk, reverse=True)
    return paths[:limit]
