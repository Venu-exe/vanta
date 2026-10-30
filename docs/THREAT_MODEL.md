# Threat model

A security tool has a threat model for itself as well as for the systems it
assesses. Both matter here.

## 1. Assets VANTA protects

| Asset | Why it matters |
|---|---|
| Authorisation boundary | Acting out of scope is the primary legal and ethical failure mode |
| Collected evidence | If it can be altered, findings are not defensible |
| Operational logs | They are the record of what was done, to whom, and when |
| Engagement data at rest | Findings often contain sensitive host and data details |
| The operator's own identity | Tooling should not leak secrets or identifiers |

## 2. Threats and mitigations

| # | Threat | Mitigation |
|---|---|---|
| T1 | **Scanning an unauthorised host** (typo in a scope, redirect to a third party) | Scope guard consulted before every request; `default_allow` is off; redirects leaving scope are blocked and annotated |
| T2 | **Accidental destructive request** (a payload that writes/deletes) | Active modules are detection-only and gated behind `--allow-active`; payloads are bounded, read-only payloads |
| T3 | **Operational exposure / detection** (noise, alerting, blocking) | Token-bucket rate limiting, per-host politeness, configurable concurrency |
| T4 | **Evidence tampering** after collection | SHA-256 hashing with a hash-chained manifest; `evidence verify` detects any change |
| T5 | **Secret leakage into logs** | Regex redaction of `Authorization`, `Cookie`, and password/token/key patterns before writing |
| T6 | **Unbounded resource use** (runaway crawl or scan) | Page/depth caps, per-module timeouts, semaphore-bounded concurrency |
| T7 | **Dependency supply-chain risk** | Zero mandatory dependencies; optional extras are well-known packages |
| T8 | **Malicious or malformed responses** crashing the tool | Network errors are values; module failures are contained per module |

## 3. Explicit non-goals

* VANTA is not a stealth/evasion framework. It does not attempt to defeat EDR or
  hide from network monitoring; it is *quiet* but not covert.
* It does not perform destructive exploitation, privilege escalation against
  live hosts, or persistence. It confirms and reports.
* It is not a substitute for authorisation. The scope guard enforces what it is
  told; the operator is responsible for telling it the truth.

## 4. Assumptions

* The operator is authorised to test every host placed in scope.
* Engagement files and results are stored on a trusted machine.
* Targets use standard HTTP/TLS semantics over TCP.
