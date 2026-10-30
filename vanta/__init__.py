"""VANTA - a red-team-minded penetration testing and bug bounty framework.

VANTA models an engagement the way a red team actually runs one: you define a
*scope*, you execute *modules* across the kill chain, every action is written to
an append-only operations log, every piece of evidence is hashed for
chain-of-custody, and the results are correlated into *attack paths* and mapped
to MITRE ATT&CK before being rendered into a report.

Nothing here is allowed to touch a host that is not explicitly in scope, and
"active" (potentially intrusive) modules are gated behind an explicit flag.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
