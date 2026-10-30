# References

Standards, specifications and tools referenced by VANTA and useful for the
dissertation's background chapter.

## Standards & frameworks

- **MITRE ATT&CK (Enterprise)** — tactic and technique taxonomy used for
  finding mapping. <https://attack.mitre.org/>
- **CVSS v3.1 Specification** — base-score metric definitions and the Roundup
  function. <https://www.first.org/cvss/v3.1/specification-document>
- **OWASP Top 10 (2021)** — web application risk categories.
  <https://owasp.org/Top10/>
- **OWASP WSTG** — Web Security Testing Guide, the methodology this project's
  phases follow. <https://owasp.org/www-project-web-security-testing-guide/>
- **CWE** — Common Weakness Enumeration identifiers attached to findings.
  <https://cwe.mitre.org/>
- **NIST SP 800-115** — Technical Guide to Information Security Testing and
  Assessment. <https://csrc.nist.gov/pubs/sp/800/115/final>
- **PTES** — Penetration Testing Execution Standard.
  <http://www.pentest-standard.org/>

## Legal & ethical

- **Computer Misuse Act 1990 (UK)** and equivalents in other jurisdictions —
  the legal reason authorisation is enforced in code.
- **Bug bounty programme policies** (HackerOne, Bugcrowd, Intigriti) — the
  practical definition of scope and safe harbour that the scope guard models.

## Prior art / comparable tools

- **Nmap** — network discovery and port scanning.
- **Nuclei** — template-driven vulnerability scanner.
- **Burp Suite / ZAP** — interactive web proxies with active scanning.
- **BloodHound** — graph-based attack-path analysis in Active Directory
  (inspiration for VANTA's attack-path graph).
- **Metasploit** — exploitation framework (VANTA deliberately stops short of
  weaponisation).

## Python / implementation

- Python `asyncio`, `ssl`, `ipaddress`, `urllib` standard-library documentation.
- Hash chains / chain-of-custody: see digital forensics literature on evidence
  integrity and tamper-evident logs.
