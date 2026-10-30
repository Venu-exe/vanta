"""MITRE ATT&CK mapping.

Rather than scattering technique IDs through modules, every category maps to a
tactic/technique pair in one table. That single source of truth is what makes
the report's ATT&CK coverage matrix possible.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

# Canonical tactic order (Enterprise ATT&CK, trimmed to what VANTA covers).
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str

    def __str__(self) -> str:
        return f"{self.id} {self.name}"


TECHNIQUES: dict[str, Technique] = {
    t.id: t
    for t in [
        Technique("T1595", "Active Scanning", "Reconnaissance"),
        Technique("T1595.001", "Scanning IP Blocks", "Reconnaissance"),
        Technique("T1595.002", "Vulnerability Scanning", "Reconnaissance"),
        Technique("T1590", "Gather Victim Network Information", "Reconnaissance"),
        Technique("T1590.002", "DNS", "Reconnaissance"),
        Technique("T1592", "Gather Victim Host Information", "Reconnaissance"),
        Technique("T1592.002", "Software", "Reconnaissance"),
        Technique("T1596", "Search Open Technical Databases", "Reconnaissance"),
        Technique("T1593", "Search Open Websites/Domains", "Reconnaissance"),
        Technique("T1190", "Exploit Public-Facing Application", "Initial Access"),
        Technique("T1133", "External Remote Services", "Initial Access"),
        Technique("T1566", "Phishing", "Initial Access"),
        Technique("T1566.002", "Spearphishing Link", "Initial Access"),
        Technique("T1059", "Command and Scripting Interpreter", "Execution"),
        Technique("T1203", "Exploitation for Client Execution", "Execution"),
        Technique("T1505.003", "Web Shell", "Persistence"),
        Technique("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
        Technique("T1078", "Valid Accounts", "Privilege Escalation"),
        Technique("T1550.002", "Pass the Hash", "Lateral Movement"),
        Technique("T1550.003", "Pass the Ticket", "Lateral Movement"),
        Technique("T1021", "Remote Services", "Lateral Movement"),
        Technique("T1558.003", "Kerberoasting", "Credential Access"),
        Technique("T1558.004", "AS-REP Roasting", "Credential Access"),
        Technique("T1558", "Steal or Forge Kerberos Tickets", "Credential Access"),
        Technique("T1110", "Brute Force", "Credential Access"),
        Technique("T1552", "Unsecured Credentials", "Credential Access"),
        Technique("T1555", "Credentials from Password Stores", "Credential Access"),
        Technique("T1040", "Network Sniffing", "Credential Access"),
        Technique("T1046", "Network Service Discovery", "Discovery"),
        Technique("T1087", "Account Discovery", "Discovery"),
        Technique("T1082", "System Information Discovery", "Discovery"),
        Technique("T1018", "Remote System Discovery", "Discovery"),
        Technique("T1083", "File and Directory Discovery", "Discovery"),
        Technique("T1590.005", "IP Addresses", "Reconnaissance"),
        Technique("T1210", "Exploitation of Remote Services", "Lateral Movement"),
        Technique("T1071.001", "Web Protocols", "Command and Control"),
        Technique("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
        Technique("T1499", "Endpoint Denial of Service", "Impact"),
        Technique("T1485", "Data Destruction", "Impact"),
        Technique("T1530", "Data from Cloud Storage", "Collection"),
    ]
}

# Module categories -> the techniques they exercise.
CATEGORY_TECHNIQUES: dict[str, list[str]] = {
    "recon": ["T1595", "T1590", "T1590.002", "T1592", "T1593"],
    "dns": ["T1590.002"],
    "subdomain": ["T1590", "T1590.002"],
    "portscan": ["T1595.001", "T1046"],
    "service": ["T1046", "T1592.002"],
    "tech-detect": ["T1592.002"],
    "tls": ["T1592.002"],
    "headers": ["T1592.002"],
    "crawler": ["T1083", "T1593"],
    "web": ["T1190"],
    "injection": ["T1190"],
    "ssrf": ["T1190"],
    "xss": ["T1190", "T1059"],
    "jwt": ["T1552", "T1550.003"],
    "auth": ["T1078", "T1110"],
    "cve": ["T1596", "T1190"],
    "intel": ["T1596"],
    "ad": ["T1558.003", "T1558.004", "T1550.002"],
    "phishing": ["T1566.002"],
}


def techniques_for(category: str, explicit: Iterable[str] = ()) -> list[str]:
    """Resolve technique IDs for a finding: explicit IDs win, else category."""
    ids = list(explicit) or list(CATEGORY_TECHNIQUES.get(category, []))
    return [tid for tid in ids if tid in TECHNIQUES]


def tactic_for(technique_id: str) -> str:
    t = TECHNIQUES.get(technique_id)
    return t.tactic if t else "Unknown"


def coverage_matrix(findings) -> dict[str, list[str]]:
    """Build a tactic -> [technique ids] matrix for the report."""
    matrix: dict[str, set[str]] = {t: set() for t in TACTIC_ORDER}
    for f in findings:
        for tid in f.attck:
            tactic = tactic_for(tid)
            matrix.setdefault(tactic, set()).add(tid)
    return {
        tactic: sorted(ids, key=lambda x: (len(x), x))
        for tactic, ids in matrix.items()
        if ids
    }


def describe(technique_id: str) -> str:
    t = TECHNIQUES.get(technique_id)
    return str(t) if t else technique_id
