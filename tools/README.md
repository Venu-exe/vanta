# Tools

Small, dependency-free companion scripts. Each is runnable standalone:

```bash
python3 tools/<tool>.py --help
```

| Tool | Purpose |
|---|---|
| [`import_scope.py`](import_scope.py) | Turn a bug-bounty programme scope (HackerOne/Bugcrowd JSON, CSV, or plain text) into a VANTA scope/engagement file. |
| [`to_sarif.py`](to_sarif.py) | Convert `results.json` into **SARIF 2.1.0** for GitHub Code Scanning / CI annotations. |
| [`compare_runs.py`](compare_runs.py) | Diff two runs and report **fixed / new / still-open** findings — ideal as a remediation gate. |

## Examples

```bash
# 1. Programme scope -> VANTA files
python3 tools/import_scope.py examples/programme.hackerone.json \
    -o scope.acme.json --engagement engagement.acme.json \
    --name acme-bounty --client "Acme Corp" \
    --authorisation "https://hackerone.com/acme"

# 2. Findings -> SARIF
python3 tools/to_sarif.py engagements/acme-bounty/results.json -o vanta.sarif

# 3. Track remediation between two runs (non-zero exit if something new appeared)
python3 tools/compare_runs.py run-week1.json run-week2.json
```

## Using the tools in CI

```yaml
- name: VANTA scan
  run: python3 -m vanta scan --engagement engagement.acme.json --modules techdetect http-headers -o out
- name: Export SARIF
  run: python3 tools/to_sarif.py out/acme-bounty/results.json -o vanta.sarif
- name: Upload to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vanta.sarif
```
