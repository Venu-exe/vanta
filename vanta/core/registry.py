"""Plugin registry and module base class.

Modules self-register with the ``@register`` decorator, and :func:`discover`
walks ``vanta.modules`` to import everything. Adding a capability is therefore:
drop a file in the right package, decorate the class, done - no central list to
edit. This is the extensibility story the dissertation will lean on.
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Type

from vanta.core.models import Finding, ModuleResult, Target

_REGISTRY: dict[str, Type["Module"]] = {}


@dataclass
class RunContext:
    """Everything a module is allowed to touch, handed in by the engine."""

    target: Any  # vanta.core.models.Target
    http: Any  # vanta.core.core.http.HttpClient
    evidence: Any  # vanta.core.evidence.EvidenceStore
    log: Any  # vanta.core.oplog.OpsLog
    config: dict[str, Any] = field(default_factory=dict)
    active: bool = False  # set only when --allow-active was passed
    offline: bool = False  # no internet; passive/local data only
    findings: list[Finding] = field(default_factory=list)
    shared: dict[str, Any] = field(default_factory=dict)  # inter-module handoff

    @property
    def base_url(self) -> str:
        """The URL base that is known to work (scheme auto-detected if needed)."""
        return self.shared.get("base_url") or self.target.base_url

    async def fetch(self, path: str = "/", **kwargs):
        """GET a path, transparently trying the opposite scheme.

        Real targets are inconsistent about redirecting HTTP->HTTPS and many
        lab/dev servers are HTTP-only, so we probe the declared scheme first and
        fall back to the other one, caching whichever answered.
        """
        if "base_url" in self.shared:
            url = self.shared["base_url"].rstrip("/") + "/" + path.lstrip("/")
            return await self.http.get(url, **kwargs)

        other = "http" if self.target.scheme == "https" else "https"
        candidates = [
            self.target.base_url,
            Target(host=self.target.host, scheme=other, port=self.target.port).base_url,
        ]
        last = None
        for base in candidates:
            url = base.rstrip("/") + "/" + path.lstrip("/")
            resp = await self.http.get(url, **kwargs)
            last = resp
            if resp.error is None and resp.status and resp.status < 500:
                self.shared["base_url"] = base
                return resp
        return last


class Module:
    """Base class for every VANTA capability."""

    name: str = "base"
    category: str = "general"
    description: str = ""
    #: Techniques the module exercises (overrides the category mapping).
    attck: tuple[str, ...] = ()
    #: Active modules can disturb a target and require --allow-active.
    active: bool = False
    #: Rough ordering hint so recon runs before exploitation.
    phase: int = 50

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    def requires(self, ctx: RunContext) -> Optional[str]:
        """Return a reason to skip, or None to run."""
        if self.active and not ctx.active:
            return "active module skipped (pass --allow-active to enable)"
        return None

    async def run(self, ctx: RunContext) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError


def register(cls: Type[Module]) -> Type[Module]:
    """Class decorator that adds a module to the global registry."""
    if not getattr(cls, "name", None) or cls.name == "base":
        raise ValueError(f"{cls.__name__} must define a unique class attribute 'name'")
    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        raise ValueError(f"duplicate module name: {cls.name!r}")
    _REGISTRY[cls.name] = cls
    return cls


def get(name: str) -> Type[Module]:
    if name not in _REGISTRY:
        raise KeyError(f"unknown module: {name!r}")
    return _REGISTRY[name]


def all_modules() -> dict[str, Type[Module]]:
    return dict(_REGISTRY)


def by_category() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, cls in _REGISTRY.items():
        out.setdefault(cls.category, []).append(name)
    for v in out.values():
        v.sort()
    return dict(sorted(out.items()))


def select(names: list[str] | None = None, categories: list[str] | None = None) -> list[Type[Module]]:
    """Resolve a module selection, sorted into kill-chain order."""
    chosen: list[Type[Module]] = []
    for name, cls in _REGISTRY.items():
        if names and name not in names:
            continue
        if categories and cls.category not in categories:
            continue
        chosen.append(cls)
    chosen.sort(key=lambda c: (c.phase, c.name))
    return chosen


def discover(package: str = "vanta.modules") -> int:
    """Import every submodule so decorators run. Returns modules loaded."""
    try:
        pkg = importlib.import_module(package)
    except ImportError:  # pragma: no cover
        return 0
    before = len(_REGISTRY)
    for info in pkgutil.walk_packages(pkg.__path__, prefix=package + "."):
        importlib.import_module(info.name)
    return len(_REGISTRY) - before


def clear() -> None:
    """Test helper: empty the registry."""
    _REGISTRY.clear()
