# Examples

Ready-to-run engagement and scope files. Copy one and edit the hosts.

| File | Scenario | Run it |
|---|---|---|
| [`engagement.demo.json`](engagement.demo.json) | **Local lab** — deliberately vulnerable server on loopback | `make demo` |
| [`engagement.scanme.json`](engagement.scanme.json) | **Real, authorised host** — `scanme.nmap.org`, which the Nmap project permits scanning | `python3 -m vanta scan -e examples/engagement.scanme.json --allow-active` |
| [`engagement.bugbounty.json`](engagement.bugbounty.json) | **Bug bounty programme** — wildcards, exclusions, low rate | edit the programme URL first |
| [`engagement.internal.json`](engagement.internal.json) | **Internal network** — CIDR ranges with carved-out exceptions | `python3 -m vanta scan -e examples/engagement.internal.json --allow-active` |
| [`engagement.api.json`](engagement.api.json) | **API review** — JWT analysis, SSRF callbacks, injection | paste a token into `jwt_tokens` first |
| [`engagement.passive.json`](engagement.passive.json) | **Passive only** — no active modules, safe everywhere | `python3 -m vanta scan -e examples/engagement.passive.json` |
| [`engagement.multi.json`](engagement.multi.json) | **Multiple targets** — findings grouped per host | `python3 -m vanta scan -e examples/engagement.multi.json --allow-active` |
| [`scope.acme.json`](scope.acme.json) | Scope object — wildcards, URLs, a CIDR and exclusions | `python3 -m vanta scope validate --scope examples/scope.acme.json api.acme.com` |
| [`scope.hosts.json`](scope.hosts.json) | Scope as a **plain JSON list** — the minimal form | `python3 -m vanta scan -t api.acme.com --scope examples/scope.hosts.json` |
| [`programme.hackerone.json`](programme.hackerone.json) | HackerOne-style exported scope, for the importer | `python3 tools/import_scope.py examples/programme.hackerone.json -o scope.json` |
| [`engagement.acme.yaml`](engagement.acme.yaml) | The YAML form (needs `PyYAML`) | `python3 -m vanta scan -e examples/engagement.acme.yaml` |

## Notes

* Wildcards (`*.acme.com`) and CIDRs are **authorisation patterns**, not
  scannable targets. Feed concrete discovered hosts back with `--target`.
* `--allow-active` is required for intrusive modules (`portscan`, `sqli`, `xss`,
  `ssrf`). Everything else is passive and safe to run broadly.
* Set `rate_limit` conservatively for third-party programmes; a blocked IP helps
  nobody.
