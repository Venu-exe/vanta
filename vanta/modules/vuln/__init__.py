"""Vulnerability modules.

These are intentionally *detection* modules: they confirm the presence of a
condition with the minimum number of requests and never exfiltrate, overwrite or
destroy data. Modules that could disturb a target are marked ``active`` and are
skipped unless the operator passes ``--allow-active``.
"""
