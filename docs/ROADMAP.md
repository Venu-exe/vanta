# Roadmap

A pragmatic backlog. Items are grouped by the value they add to the tool and to
a final-year write-up.

## Near term (make the demo richer)

- [ ] **JSON/YAML schema validation** for engagement files with clear errors.
- [ ] **Redirect-aware crawler** outcomes surfaced as findings (open redirects).
- [ ] **WordPress/Drupal/Joomla** heuristic modules built on `techdetect`.
- [ ] **CORS misconfiguration** module (origin reflection, credentialed wildcards).
- [ ] **Subdomain takeover** detection via dangling CNAME fingerprints.

## Medium term (depth)

- [ ] **Passive intel sources** (certificate transparency `crt.sh`, NVD API)
      behind `--offline`-aware fetchers, cached locally.
- [ ] **Graph centrality** — rank hosts by betweenness to find the most
      *pivotal* asset rather than only the most severe finding.
- [ ] **Report templating** with a pluggable theme and a PDF export path.
- [ ] **SARIF/CSAF export** so findings feed CI and ticketing systems.
- [ ] **Resume/checkpoint** — persist engine state so long engagements survive
      interruption.

## Long term (research-flavoured)

- [ ] **Attack-path prediction**: extend `leads_to` edges into a scoring model
      that estimates the probability an attacker completes a full path.
- [ ] **Control-coverage mapping** against CIS Benchmarks / NIST 800-53.
- [ ] **Differential scanning** — re-run an engagement and diff findings to show
      remediation progress over time.
- [ ] **Optional Active Directory module group** (BloodHound-style path analysis,
      Kerberoasting) for internal engagements, staying detection-first.

## Deliberately out of scope

- Weaponised exploitation, persistence, C2, or evasion.
- Anything that violates a target's authorisation boundary.

## Definition of done for a new module

1. Lives under the correct `modules/<category>/` package.
2. Decorated with `@register`, unique `name`, honest `active` flag, sensible
   `phase`.
3. Non-destructive, scope-aware (uses `ctx.http`/`ctx.fetch`).
4. Returns `Finding`s with severity, confidence, evidence, remediation and
   ATT&CK category.
5. Covered by at least one test or exercised by the demo lab.
