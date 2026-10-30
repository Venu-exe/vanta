# Dissertation notes

How VANTA maps onto a typical final-year project: chapters, the questions it
answers, the evaluation you can actually run, and the contributions to claim.

## 1. Problem statement

Offensive security tooling used by students and junior testers is typically a
collection of scripts that emit raw output. It rarely models **authorisation**,
**correlation**, or **evidential integrity** — the properties that separate
professional assessment from unauthorised scanning. VANTA addresses that gap
with a framework whose architecture treats safety, traceability and
correlation as first-class design concerns rather than add-ons.

## 2. Research questions

1. Can a plugin architecture deliver broad coverage while keeping the
   trust boundary (authorisation) in one auditable place?
2. Does mapping findings to an attack-path graph produce more actionable results
   than a flat severity list?
3. Can chain-of-custody integrity be provided by a lightweight hash-chained
   manifest without external tooling?
4. What is the cost (runtime/requests) of enforcing scope, rate limiting and
   evidence capture on every action?

## 3. Suggested chapter structure

| Chapter | Content | Source in this repo |
|---|---|---|
| 1. Introduction | Motivation, aims, objectives, scope | `README.md` |
| 2. Background | Pentest methodology, kill chain, MITRE ATT&CK, CVSS, existing tools (Nmap, Nuclei, Burp) | `docs/METHODOLOGY.md`, `docs/REFERENCES.md` |
| 3. Requirements & Threat Model | Functional/non-functional requirements; why authorisation and evidence matter | `docs/THREAT_MODEL.md` |
| 4. Design | Component diagrams, plugin registry, scope algorithm, risk model, attack graph | `docs/ARCHITECTURE.md` |
| 5. Implementation | Engine, modules, report layer, key code excerpts | `vanta/core/`, `vanta/modules/` |
| 6. Testing | Unit tests for safety-critical parts; end-to-end reproducible demo | `tests/`, `scripts/demo.sh` |
| 7. Evaluation | Experiments below | this file |
| 8. Discussion & Future Work | Limitations, roadmap, ethical reflection | `docs/ROADMAP.md` |

## 4. Evaluation plan (what to actually measure)

**E1 — Authorisation correctness.** Run the scope guard test matrix
(wildcards, CIDRs, exclusions, look-alike domains) and report pass rate.
Argument: the safety property is *verified*, not asserted.

**E2 — Detection efficacy.** Run the demo lab, which deliberately introduces a
known set of flaws, and report true/false positives against a ground-truth list.
Include the seeded flaws table.

**E3 — Correlation value.** Compare the flat finding list against the derived
attack paths; show that attack paths surface severity-with-context (e.g. an
exposed port plus a weak credential is more important than either alone).

**E4 — Operational cost.** Measure requests issued and wall-clock time with
rate limiting on vs off, and with evidence capture on vs off. Shows the price of
the safety features.

**E5 — Evidence integrity.** Collect artefacts, verify the chain, tamper with a
byte, and show `evidence verify` fails. Demonstrates the custody property.

Results in E1–E5 are all reproducible with the bundled lab and tests, which is
the point: the evaluation runs on a marker's machine without external targets.

## 5. Contributions to claim

1. A framework that treats **authorisation as an enforced, testable control**
   rather than documentation.
2. **Attack-path correlation** layered on a conventional scanning pipeline,
   with ATT&CK mapping and a reproducible risk score.
3. A **lightweight, dependency-free chain-of-custody** mechanism for evidence.
4. A **reproducible vulnerable lab** enabling safe, repeatable evaluation of
   offensive tooling.

## 6. Limitations (state these honestly)

* Detection, not exploitation: the tool confirms weaknesses but does not chain
  them automatically against live hosts.
* The CVE knowledge base is a small sample; it demonstrates the pipeline rather
  than providing authoritative coverage.
* Subdomain enumeration is wordlist-based; it does not (yet) consult passive
  sources like certificate transparency.
* Performance on very large scopes is bounded by the single-process async model.

## 7. Ethical reflection (often a marking criterion)

Discuss the dual-use nature of offensive tooling, why active modules default to
off, how the scope guard encodes an ethical commitment in code, and the
distinction between authorisation (legal permission) and scope (the technical
boundary that implements it).
