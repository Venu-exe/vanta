#!/usr/bin/env bash
# End-to-end demo: start the local vulnerable lab, scan it with VANTA, and open
# the report. Everything stays on loopback.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${PORT:-8000}"
OUT="${OUT:-engagements}"

echo "[*] starting vulnerable lab on 127.0.0.1:${PORT}"
python3 lab/vulnerable_server.py --port "${PORT}" >/dev/null 2>&1 &
LAB_PID=$!
trap 'kill ${LAB_PID} 2>/dev/null || true' EXIT
sleep 1

echo "[*] scanning (active modules enabled - loopback lab only)"
python3 -m vanta scan \
  --engagement examples/engagement.demo.json \
  --modules subdomains techdetect http-headers crawler sqli xss ssrf cve-correlate \
  --allow-active \
  --metadata "{\"scheme\":\"http\",\"port\":${PORT}}" \
  --output "${OUT}"

echo
echo "[*] verifying evidence chain of custody"
python3 -m vanta evidence verify "${OUT}/demo-lab"

echo
echo "[+] done. Report: ${OUT}/demo-lab/report.md and report.html"
