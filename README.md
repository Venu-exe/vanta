<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=42&pause=1000&color=A855F7&center=true&vCenter=true&width=520&lines=VANTA;Red-Team-Minded+Pentest+Framework" alt="VANTA" />

**A red-team-minded penetration testing & bug-bounty framework.**

Scopes that fail closed. Attack paths, not flat lists. Evidence you can prove.

[![License: MIT](https://img.shields.io/badge/License-MIT-a855f7.svg?style=flat-square)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab.svg?style=flat-square&logo=python&logoColor=white)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-35%20passing-22c55e.svg?style=flat-square)](#testing)
[![Dependencies](https://img.shields.io/badge/runtime%20deps-0-22c55e.svg?style=flat-square)](#why-vanta)
[![MITRE ATT&CK](https://img.shields.io/badge/mapped%20to-MITRE%20ATT%26CK-red.svg?style=flat-square)](docs/METHODOLOGY.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-a855f7.svg?style=flat-square)](#contributing)

</div>

---

> Most student pentest tools are a folder of scripts that print output.
> **VANTA models the discipline of offensive work** — authorisation, correlation,
> and evidential integrity are baked into the architecture, not bolted on.

```console
$ python3 -m vanta scan --engagement examples/engagement.demo.json --allow-active

==============================================================
  Engagement : demo-lab
  Targets    : 1
  Findings   : 12
  Risk score : 40.1/100  (grade D)
  Severity   : critical:2, high:5, medium:2, low:1
  Attack paths:
    - 127.0.0.1 → SQL injection in parameter 'id'
    - 127.0.0.1 → Potential SSRF in parameter 'url'
==============================================================
```

---

## Table of contents

- [Why VANTA](#why-vanta)
- [Quickstart](#quickstart)
- [Usage](#usage)
- [What it does](#what-it-does)
- [Adding a module in 12 lines](#adding-a-module-in-12-lines)
- [Testing](#testing)
- [Documentation](#documentation)
- [Ethics & legal](#ethics--legal)
- [Contributing](#contributing)

---

## Why VANTA

| Concern | The usual script | **VANTA** |
|---|---|---|
| **Authorisation** | A comment saying "don't test out of scope" | `Scope` guard rejects out-of-scope hosts **before any packet is sent**; CIDRs, wildcards, exclusions; fails closed |
| **Results** | A flat dump of findings | Findings chained into ranked **attack paths** (host → port → service → impact) |
| **Threat context** | None | Every finding mapped to **MITRE ATT&CK**, with a tactic coverage matrix in the report |
| **Evidence** | A screenshot | SHA-256 hashed artefacts + a **hash-chained custody manifest** you can independently verify |
| **Opsec** | Hammer the target | Token-bucket **rate limiting**, per-host politeness, secret redaction, intrusive checks **off by default** |
| **Setup** | `pip install` a dozen things | **Zero mandatory dependencies** — pure standard library |

**Star this repo** ⭐ if you think offensive tooling should teach the discipline, not just the payloads.

---

## Quickstart

```bash
git clone https://github.com/Venu-exe/vanta.git && cd vanta

# 0. No install required:
python3 -m vanta modules

# 1. Watch the safety model work — this exits non-zero on the out-of-scope host:
python3 -m vanta scope validate --scope examples/scope.acme.json \
    api.acme.com billing.acme.com evil.example.net

# 2. Run the full end-to-end demo against a bundled vulnerable lab (loopback only):
make demo
```

```console
$ make demo

[*] starting vulnerable lab on 127.0.0.1:8000
[*] scanning (active modules enabled - loopback lab only)
  → 12 findings, risk 40.1/100, 2 attack paths
[*] verifying evidence chain of custody
  chain of custody intact engagements/demo-lab/custody.jsonl
[+] done. Report: engagements/demo-lab/report.md and report.html
```

Optional niceties (the tool works without them):

```bash
python3 -m pip install -e ".[ui,yaml,dev]"   # rich output, YAML scopes, pytest
```

---

## Usage

```bash
# Scan using an engagement file (recommended)
python3 -m vanta scan --engagement examples/engagement.demo.json --allow-active

# Or inline, against specific targets
python3 -m vanta scan \
    --target app.example.com \
    --scope examples/scope.acme.json \
    --modules subdomains techdetect http-headers crawler \
    --rate 5 --concurrency 8

# Run a whole kill-chain phase, or re-render a saved report
python3 -m vanta scan -t app.example.com -c recon
python3 -m vanta report engagements/app-example-com/results.json

# Prove nothing was tampered with after collection
python3 -m vanta evidence verify engagements/app-example-com
```

| Flag | Meaning |
|---|---|
| `--allow-active` | Enables intrusive modules (portscan, sqli, xss, ssrf). **Off by default.** |
| `--scope FILE` | Overrides the authorisation boundary. |
| `--rate N` | Global requests/second (politeness). |
| `--category CAT` | Run every module in a category. |
| `--offline` | Never make external network calls. |
| `--metadata JSON` | Merge extra config (ports, callbacks, tokens, ...). |

---

## What it does

<table>
<tr><td width="50%" valign="top">

**Reconnaissance**
- `subdomains` — DNS enumeration, flags admin/staging/CI labels
- `portscan` — async TCP connect scan + banner grabbing
- `techdetect` — servers, frameworks, CDN/WAF fingerprinting

**Service inspection**
- `tls-audit` — cert inventory, expiry, legacy TLS 1.0/1.1
- `http-headers` — CSP/HSTS/framing + cookie flag audit
- `crawler` — same-origin BFS of URLs, parameters, forms

</td><td width="50%" valign="top">

**Vulnerability identification** *(detection only)*
- `sqli` — error-signature + boolean differential
- `xss` — non-executing canary reflection
- `ssrf` — callback canary behavioural probe
- `jwt` — `alg:none`, weak HMAC secrets, missing expiry
- `cve-correlate` — offline CVE knowledge base

**Output**
- Markdown + self-contained HTML reports
- Attack-path graph (Graphviz DOT export)
- SHA-256 evidence custody manifest

</td></tr>
</table>

---

## Adding a module in 12 lines

Drop a file under `vanta/modules/<category>/` and decorate a class — `vanta modules`
picks it up immediately. No central list to edit.

```python
from vanta.core.models import Confidence, Finding, Severity
from vanta.core.registry import Module, RunContext, register

@register
class MyCheck(Module):
    name = "my-check"
    category = "web"
    description = "what this does"
    phase = 40            # kill-chain ordering hint
    active = False        # True => requires --allow-active

    async def run(self, ctx: RunContext) -> list[Finding]:
        resp = await ctx.fetch()                 # scope-safe, rate-limited
        ctx.evidence.store("http", "root", resp.body)
        return [Finding(
            title="Example", module=self.name, target=ctx.target.host,
            severity=Severity.LOW, confidence=Confidence.FIRM,
        )]
```

---

## Testing

```bash
python3 -m pytest        # 35 tests, no network required
```

The suite covers the parts that must not break:

| Layer | What's verified |
|---|---|
| Scope guard | wildcards, CIDRs, exclusions, look-alike domains |
| Scoring | CVSS v3.1 vectors checked against published reference scores |
| Registry | discovery, metadata, kill-chain ordering |
| Graph / ATT&CK | path derivation, `leads_to` chaining, tactic grouping |
| Evidence | hash verification **and deliberate tamper detection** |
| Engine | full run with a fake module — offline, deterministic |

---

## Documentation

| Doc | Contents |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | Component design, data flow, scope algorithm, risk model |
| [Methodology](docs/METHODOLOGY.md) | Kill-chain phases, module → ATT&CK mapping |
| [Threat model](docs/THREAT_MODEL.md) | What VANTA protects, threats, explicit non-goals |
| [Roadmap](docs/ROADMAP.md) | Near / medium / long-term plans |
| [Dissertation notes](docs/DISSERTATION-NOTES.md) | Chapter mapping + reproducible evaluation plan |
| [References](docs/REFERENCES.md) | Standards, prior art, reading list |

---

## Ethics & legal

VANTA is for **authorised** testing only: systems you own, a lab you own, or a
target covered by a signed authorisation or a public bug-bounty policy. The
scope guard is a technical control, not a licence. Active modules are off by
default for a reason. **If you are unsure whether you may test something, you
may not.**

---

## Contributing

Issues and PRs welcome. A module is "done" when it is non-destructive,
scope-aware, returns evidence-backed `Finding`s with remediation, and is covered
by a test or exercised by the demo lab. See
[Roadmap § Definition of done](docs/ROADMAP.md) for the checklist.

## License

MIT — see [LICENSE](LICENSE).

<div align="center">

**Built as a final-year project. Engineered like a real tool.**

⭐ Star it if it taught you something.

</div>
