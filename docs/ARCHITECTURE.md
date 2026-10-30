# Architecture

This document explains how VANTA is put together and *why*. It is written to be
lifted almost directly into a dissertation's design chapter.

## 1. Design principles

1. **Fail closed on authorisation.** The scope guard is consulted before every
   network action. Absence of a scope is not permission.
2. **Separate orchestration from capability.** The engine knows nothing about
   SQL injection; modules know nothing about scheduling. Each can be tested
   alone.
3. **Everything is data.** Modules return `Finding` dataclasses. The same object
   serialises to JSON, Markdown and HTML, so the report layer never re-parses
   anything.
4. **Zero mandatory dependencies.** The standard library is sufficient to run
   the tool, which keeps it demoable and gradable anywhere.
5. **Safety is a feature, not a footnote.** Rate limiting, secret redaction and
   gating of intrusive checks are first-class, not afterthoughts.

## 2. Component map

```
                    ┌──────────────────────────────────────────────┐
   engagement.json  │                  cli.py                      │
   scope.json       │  scan · report · modules · scope · evidence  │
                    └───────────────┬──────────────────────────────┘
                                    │ Engagement + Scope
                                    ▼
                    ┌──────────────────────────────────────────────┐
                    │                 engine.py                    │
                    │  build_targets → enforce scope → run modules │
                    │  → collect findings → correlate → persist    │
                    └───┬───────────┬───────────┬──────────┬───────┘
                        │           │           │          │
              ┌─────────▼──┐  ┌─────▼─────┐ ┌───▼─────┐ ┌──▼────────┐
              │ registry   │  │  http.py  │ │ evidence│ │  oplog    │
              │ + modules  │  │ (scope-   │ │ store   │ │ (JSONL)   │
              │            │  │  aware,   │ │ (hash   │ │           │
              │            │  │  limited) │ │  chain) │ │           │
              └─────┬──────┘  └───────────┘ └─────────┘ └───────────┘
                    │ list[Finding]
                    ▼
       ┌──────────────────────────┬───────────────────────────┐
       │ scoring.py (CVSS + risk) │ graph.py (attack paths)   │
       │ attck.py  (technique map)│ report/ (md + html)       │
       └──────────────────────────┴───────────────────────────┘
```

## 3. Execution flow

1. **Load.** `cli.py` parses arguments and (`config.py`) loads an
   `Engagement` and a `Scope` from JSON or YAML.
2. **Construct.** `Engine.__init__` opens the ops log and evidence store under
   `engagements/<name>/`, and builds one rate-limited `HttpClient` bound to the
   scope.
3. **Target.** `build_targets` turns the scope into concrete `Target`s. Wildcards
   and CIDRs cannot be scanned directly and are skipped (a real assessment feeds
   discovered hosts back in).
4. **Execute.** For each target, modules run in `phase` order. Before each,
   `scope.assert_in_scope(host)` is checked. `RunContext` is the only handle a
   module gets; it exposes the HTTP client, evidence store, logger and a
   `shared` dict for inter-module handoff.
5. **Collect.** Each module returns `list[Finding]`. Errors are captured per
   module so one failure cannot abort the engagement.
6. **Correlate.** `graph.py` builds a per-host graph and derives ranked attack
   paths; `scoring.py` aggregates a risk score.
7. **Persist.** `results.json`, one DOT graph per host, and the ops log are
   written; the report layer renders Markdown and HTML.

## 4. The scope guard

`Scope._match_one` resolves patterns in this order:

1. **CIDR** — validated with `ipaddress` so a URL like
   `https://api.example.com/v1` is *not* mistaken for a network.
2. **Scheme** stripped (`https://` → host).
3. **Path/query/port** stripped, leaving a hostname.
4. Match by: exact equality → `*.suffix` wildcard → bare-domain suffix → glob.

Exclusions are evaluated first and always win, mirroring how bug-bounty
programmes publish scope. `default_allow` is opt-in and off by default.

## 5. Risk model

Base scores use a from-spec implementation of **CVSS v3.1**
(`scoring.py::cvss_base_score`). The engagement score is a saturating aggregate:

```
score = 100 · (1 − exp(−Σ (base_i · confidence_i) / 120))
```

where `confidence ∈ {1.0 confirmed, 0.8 firm, 0.5 tentative}`. The exponential
keeps the result in `[0,100]` and stops ten criticals from saturating the scale.
The result maps to letter grades A–F. This is deliberately simple and
explainable — a report reader can reproduce the number by hand.

## 6. Attack-path graph

Nodes are `host`, `host:port`, `service` and `finding`; edges encode
containment and exploitation order. `leads_to` on a finding adds an explicit
escalation edge (e.g. *exposed admin panel → default creds → RCE*). Paths are
derived with a breadth-first search from the host node to each non-trivial
finding and ranked by summed CVSS. The graph exports to Graphviz DOT for the
architecture diagram in the report.

## 7. Evidence integrity

`EvidenceStore` writes each artefact under
`engagements/<name>/evidence/artefacts/` and appends a manifest line containing
the artefact's SHA-256 and the hash of the previous manifest line. That makes
the manifest a **hash chain**: altering any entry invalidates everything after
it. `vanta evidence verify` recomputes every hash and reports mismatches — the
chain-of-custody property an examiner expects.

## 8. Extensibility

`@register` inserts a class into a module-level dict. `discover()` walks the
`vanta.modules` package with `pkgutil.walk_packages` and imports every
submodule, so decorators execute. There is no list to keep in sync: a new file
is a new capability.

## 9. Failure handling

* A module raising is caught, recorded as `ModuleResult.error`, and the run
  continues.
* Network errors are values (`Response.error`), not exceptions, so modules
  branch on `resp.ok`.
* `asyncio.wait_for` caps each module's wall-clock time.
* Redirects leaving scope are blocked and annotated, not followed.
