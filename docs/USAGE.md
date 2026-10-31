# Usage guide

How to use VANTA on a **real** target, end to end. Replace the example hosts
with your own authorised target.

> **Rule zero.** Only test what you are allowed to test: systems you own, a lab
> you own, or a target covered by a signed authorisation or a public bug-bounty
> policy. VANTA will happily refuse out-of-scope hosts for you, but it cannot
> grant you permission.

---

## 1. Pick a target you are authorised to test

Good starting points that are *publicly authorised*:

* `scanme.nmap.org` — the Nmap project explicitly authorises scanning it.
* Your own VPS, homelab, or a deliberately-vulnerable VM.
* A bug-bounty programme's in-scope assets (respect the policy).

## 2. Write the scope first

Everything flows from the scope. Two ways:

**Hand-written:**

```json
{
  "label": "acme programme",
  "in_scope": ["acme.com", "*.acme.com", "api.acme.com"],
  "out_of_scope": ["billing.acme.com", "status.acme.com"]
}
```

**Imported from a programme:**

```bash
python3 tools/import_scope.py examples/programme.hackerone.json \
    -o scope.acme.json \
    --engagement engagement.acme.json \
    --name acme-bounty --client "Acme Corp"
```

**Verify it before you touch anything:**

```console
$ python3 -m vanta scope validate --scope examples/scope.acme.json \
    api.acme.com billing.acme.com evil.example.net

  ALLOW  api.acme.com: IN SCOPE
  DENY   billing.acme.com: OUT OF SCOPE (explicit exclusion)
  DENY   evil.example.net: OUT OF SCOPE
$ echo $?
2
```

A non-zero exit code means at least one host was refused. This is your safety
net — wire it into a pre-flight check.

## 3. Start passive, then go active

**Step A — passive recon (no `--allow-active`).** DNS lookups and a few GETs
only. Safe to run against a programme's whole scope.

```console
$ python3 -m vanta scan --target example.com --name example-com \
    -m techdetect http-headers tls-audit --rate 2 -o engagements

  Engagement : example-com
  Targets    : 1
  Findings   : 2
  Risk score : 6.4/100  (grade A)
  Severity   : critical:0, high:0, medium:1, low:0
```

**Step B — active checks (`--allow-active`).** Adds port scanning and
detection-only injection probes. Keep the rate low.

```console
$ python3 -m vanta scan --engagement examples/engagement.scanme.json \
    --allow-active --output engagements

  → [info] portscan.scan host=scanme.nmap.org ip=2600:3c01::f03c:91ff:fe18:bb2f ports=70
  → [info] module.done module=portscan host=scanme.nmap.org findings=3 ms=2904
  → [info] module.done module=techdetect host=scanme.nmap.org findings=1 ms=2107
  → [info] module.done module=http-headers host=scanme.nmap.org findings=1 ms=1776
  → [info] engine.done findings=6 risk=6.4 grade=A duration=25.46
```

Real output from that run (excerpt):

| Severity | Finding | Detail |
|---|---|---|
| Medium | 6 missing security header(s) | no CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| Info | 2 open TCP ports | `22, 80` |
| Info | Exposed service `:22` | banner `SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13` |

That banner is a real, useful signal: it fingerprints the SSH version, which is
exactly what an attacker would note.

## 4. Read the outputs

Every run writes a folder under `engagements/<name>/`:

| File | What it is |
|---|---|
| `report.md` | Full report — feeds your notes and converts to PDF |
| `report.html` | Self-contained shareable report (email it, it just works) |
| `results.json` | Machine-readable findings for tooling and diffing |
| `ops.jsonl` | Append-only log of every action taken |
| `evidence/custody.jsonl` | Hash-chained evidence manifest |
| `graph-<host>.dot` | Attack-path graph, render with Graphviz |

Open the report:

```bash
xdg-open engagements/scanme-nmap-org/report.html   # or: open / start
```

Prove the evidence wasn't altered:

```console
$ python3 -m vanta evidence verify engagements/scanme-nmap-org
  chain of custody intact (engagements/scanme-nmap-org/custody.jsonl)
```

## 5. Track remediation over time

Re-run later and diff:

```bash
python3 tools/compare_runs.py engagements/acme/week1/results.json \
                             engagements/acme/week2/results.json
```

```text
Risk score: 40.1 -> 12.5  (▼ improved)

FIXED (2)
  ✓ [critical] sqli      SQL injection in parameter 'id' (app.acme.com)
  ✓ [high    ] xss       Reflected XSS in parameter 'q' (app.acme.com)

NEW (1)
  ✗ [medium  ] headers   3 missing security header(s) (staging.acme.com)

STILL OPEN (1)
  · [low     ] tls-audit TLS certificate expiring soon (api.acme.com)
```

Exit code is `1` when new findings appear — drop it into CI as a gate.

## 6. Feed findings into CI

```bash
python3 -m vanta scan --engagement engagement.acme.json --modules techdetect http-headers -o out
python3 tools/to_sarif.py out/acme-bounty/results.json -o vanta.sarif
```

Then upload `vanta.sarif` with `github/codeql-action/upload-sarif@v3` and your
findings appear as PR annotations.

## 7. Common recipes

```bash
# Recon only, whole programme scope, quiet
python3 -m vanta scan -e examples/engagement.passive.json -q

# One phase at a time
python3 -m vanta scan -t app.acme.com -c recon
python3 -m vanta scan -t app.acme.com -c vuln --allow-active

# Several hosts at once (read from a scope list)
python3 -m vanta scan -t staging.acme.com -t api.acme.com \
    --scope examples/scope.acme.json -m techdetect http-headers

# Offline (no external calls) — for air-gapped labs
python3 -m vanta scan -t 10.0.0.5 --offline -m techdetect http-headers

# Tune politeness for a sensitive programme
python3 -m vanta scan -e engagement.acme.json --rate 2 --concurrency 3
```

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `Connection refused`, all findings zero | Wrong scheme/port. The client auto-tries the other scheme, but set `"scheme"`/`"port"` in metadata (see `examples/engagement.demo.json`). |
| Active modules "skipped" | Add `--allow-active`. |
| Injection modules find nothing | They only test URLs the crawler reached. Check `results.json` → the crawler finding lists parameters. |
| Too noisy / target returns 429 | Lower `--rate` and `--concurrency`. |
| CIDR scope scans nothing | CIDRs cannot be enumerated directly — feed discovered hosts back with `-t`. |
| `yaml` errors on load | YAML needs `pip install PyYAML`; JSON always works. |
