"""Scope guard - the single most important safety control in VANTA.

Before *any* module touches *any* host, the engine asks the scope guard whether
the host is authorised. This is not a nicety: it is the difference between a
pentest and a crime. The guard supports domains with wildcards, CIDR ranges,
explicit exclusions, and an optional default-deny mode.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Iterable


class ScopeViolation(RuntimeError):
    """Raised when something tries to act on an out-of-scope asset."""


@dataclass
class Scope:
    """An authorisation boundary.

    ``in_scope`` accepts domain patterns (``*.example.com``, ``example.com``),
    bare hostnames, URLs, and CIDR ranges. ``out_of_scope`` always wins, so you
    can carve an exception out of a broad wildcard.
    """

    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    default_allow: bool = False
    label: str = "default"

    # -- construction -----------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "Scope":
        data = data or {}
        return cls(
            in_scope=list(data.get("in_scope", data.get("inScope", []))),
            out_of_scope=list(data.get("out_of_scope", data.get("outOfScope", []))),
            default_allow=bool(data.get("default_allow", False)),
            label=str(data.get("label", "default")),
        )

    @classmethod
    def from_iterable(cls, hosts: Iterable[str], label: str = "inline") -> "Scope":
        return cls(in_scope=list(hosts), label=label)

    # -- matching ---------------------------------------------------------
    def _matches_any(self, host: str, patterns: Iterable[str]) -> bool:
        host = host.strip().lower().rstrip(".")
        for raw in patterns:
            pattern = str(raw).strip().lower()
            if not pattern:
                continue
            if self._match_one(host, pattern):
                return True
        return False

    @staticmethod
    def _match_one(host: str, pattern: str) -> bool:
        # CIDR first: a network contains '/' and must not be split apart.
        if _looks_like_cidr(pattern):
            try:
                net = ipaddress.ip_network(pattern.strip(), strict=False)
                addr = ipaddress.ip_address(host)
                return addr in net
            except ValueError:
                return False

        # Strip scheme so "https://api.example.com/x" becomes a hostname.
        if "://" in pattern:
            pattern = pattern.split("://", 1)[1]
        # Strip path/query, then a port, but leave IPv6 literals intact.
        pattern = pattern.split("/", 1)[0].split("?", 1)[0].rstrip(".")
        if ":" in pattern and not pattern.startswith("["):
            pattern = pattern.split(":", 1)[0]

        # Exact hostname or IP.
        if host == pattern:
            return True

        # Wildcard forms: "*.example.com" matches "api.example.com" but NOT
        # "example.com" itself (mirrors how bug bounty platforms define scope).
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return host.endswith("." + suffix)

        # Bare domain also authorises its subdomains - the common expectation.
        if host.endswith("." + pattern):
            return True

        # Fall back to glob for exotic patterns.
        return fnmatch.fnmatch(host, pattern)

    def is_in_scope(self, host: str) -> bool:
        host = host.strip().lower()
        if self._matches_any(host, self.out_of_scope):
            return False
        if self._matches_any(host, self.in_scope):
            return True
        return self.default_allow

    def assert_in_scope(self, host: str) -> None:
        if not self.is_in_scope(host):
            raise ScopeViolation(
                f"refusing to act on out-of-scope host {host!r} (scope={self.label!r})"
            )

    # -- helpers ----------------------------------------------------------
    @property
    def is_empty(self) -> bool:
        return not self.in_scope and not self.default_allow

    def explain(self, host: str) -> str:
        if self.is_in_scope(host):
            return f"{host}: IN SCOPE"
        if self._matches_any(host, self.out_of_scope):
            return f"{host}: OUT OF SCOPE (explicit exclusion)"
        return f"{host}: OUT OF SCOPE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "in_scope": self.in_scope,
            "out_of_scope": self.out_of_scope,
            "default_allow": self.default_allow,
        }


def _looks_like_cidr(value: str) -> bool:
    """True only for a genuine ``address/prefix`` network, not a URL path."""
    if "/" not in value:
        return False
    _addr, _, prefix = value.strip().partition("/")
    if not prefix.isdigit():
        return False
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return True
    except ValueError:
        return False
