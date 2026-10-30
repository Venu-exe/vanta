# Methodology

VANTA follows a Kill Chain / ATT&CK-aligned methodology. Each phase lists the
modules that realise it, the ATT&CK tactic it maps to, and the artefacts it
produces.

| Phase | Goal | Modules | ATT&CK tactic | Artefacts |
|---|---|---|---|---|
| 1. Scope & Rules of Engagement | Fix the legal boundary | `scope`, `config` | — | `engagement.json`, `scope.json` |
| 2. Reconnaissance | Map the external surface | `subdomains`, `portscan`, `techdetect` | Reconnaissance (TA0043) | DNS records, open ports, tech fingerprint |
| 3. Service inspection | Understand the exposed services | `tls-audit`, `http-headers`, `crawler` | Reconnaissance / Discovery | TLS inventory, header gaps, URL & parameter map |
| 4. Vulnerability identification | Confirm weaknesses | `sqli`, `xss`, `ssrf`, `jwt`, `cve-correlate` | Initial Access (TA0001) | Evidence-backed findings |
| 5. Correlation | Turn findings into paths | `graph`, `scoring` | — | Attack paths, risk score |
| 6. Reporting | Communicate risk | `report/` | — | Markdown + HTML report, custody manifest |

## Phase detail

### 2. Reconnaissance
**Subdomains.** Resolves a curated label list against the scope apex. Only names
that are themselves in scope are queried. Sensitive labels (`admin`, `staging`,
`jenkins`) are escalated to *Low*.

**Port scan.** Connect()-based scan of a common-port set (extensible via the
engagement file). Banner grabbing tags services; dangerous exposures (Redis,
MongoDB, Docker daemon, Elasticsearch) are raised to *Medium*.

**Tech detect.** Passive fingerprint from `Server`, `X-Powered-By`, body markers
and CDN/WAF headers. Feeds the CVE module through shared state.

### 3. Service inspection
**TLS audit.** Certificate inventory (subject, issuer, expiry), plus probes for
legacy TLS 1.0/1.1.

**Headers.** Checks CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`, `Permissions-Policy`, and cookie flags.

**Crawler.** Same-origin BFS (depth- and page-bounded) collecting URLs,
parameters and forms, with a finding for sensitive forms submitted via GET.

### 4. Vulnerability identification
All *detection* only — the modules prove a condition with the minimum requests
and never write, delete or exfiltrate.

* **SQLi** — error-signature matching across MySQL/PostgreSQL/MSSQL/Oracle/
  SQLite, plus an `AND 1=1` vs `AND 1=2` boolean differential to cut false
  positives.
* **XSS** — a unique non-executing canary is reflected; confirmed only when
  returned verbatim.
* **SSRF** — a callback URL is substituted into URL-like parameters; a change in
  status/length or a reflected loopback address is the signal.
* **JWT** — offline decode; flags `alg:none`, guessable HMAC secrets and missing
  expiry.
* **CVE correlation** — fingerprinted components are matched against a local
  knowledge base with version-range logic.

### 5. Correlation
Findings become an attack-path graph per host; paths are ranked by summed CVSS.
An engagement risk score (see *Architecture §5*) summarises overall posture.

## Testing strategy

| Layer | Approach |
|---|---|
| Scope guard | Unit tests for wildcards, CIDRs, exclusions, look-alike domains |
| Scoring | Parametrised CVSS vectors checked against published reference scores |
| Registry | Discovery, metadata completeness, kill-chain ordering |
| Graph / ATT&CK | Path derivation, `leads_to` chaining, tactic grouping |
| Evidence | Hash verification and deliberate tamper detection |
| Engine | End-to-end run with a fake module (**no network required**) |

Run everything with `python3 -m pytest`.

## Reproducibility

The bundled lab (`lab/vulnerable_server.py`) plus `scripts/demo.sh` reproduce a
full engagement on loopback, so every number in a report can be regenerated on a
marker's machine with two commands.
