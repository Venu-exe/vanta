"""Configuration / engagement loading.

Scopes and engagement definitions can be JSON (always available) or YAML (if
PyYAML is installed). Keeping a JSON path that needs zero dependencies means the
tool is runnable on a bare machine.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vanta.core.models import Engagement
from vanta.core.scope import Scope


class ConfigError(ValueError):
    pass


def load_document(path: str | Path) -> dict[str, Any]:
    """Load a JSON or YAML document."""
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"file not found: {p}")
    text = p.read_text(encoding="utf-8")
    suffix = p.suffix.lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise ConfigError(
                "YAML input requires PyYAML (pip install PyYAML) or use JSON"
            ) from exc
        return yaml.safe_load(text) or {}
    if suffix == ".json":
        return json.loads(text)
    # Unknown extension: try JSON, fall back to YAML.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return load_document_yaml(text, p)


def load_document_yaml(text: str, p: Path) -> dict[str, Any]:  # pragma: no cover
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise ConfigError(f"cannot parse {p}: install PyYAML or use JSON") from exc
    return yaml.safe_load(text) or {}


def load_engagement(path: str | Path) -> tuple[Engagement, Scope]:
    data = load_document(path)
    if not isinstance(data, dict):
        raise ConfigError("engagement document must be a mapping/object")

    scope_doc = data.get("scope", {})
    if isinstance(scope_doc, list):
        scope_doc = {"in_scope": scope_doc}
    scope = Scope.from_dict(scope_doc)

    eng = Engagement(
        name=data.get("name", "untitled-engagement"),
        client=data.get("client", ""),
        authorisation_reference=data.get(
            "authorisation_reference", data.get("authorization", "")
        ),
        scope=scope.to_dict(),
        modules=list(data.get("modules", [])),
        metadata=data.get("metadata", {}),
    )
    return eng, scope


def load_scope(path: str | Path) -> Scope:
    data = load_document(path)
    if isinstance(data, list):
        return Scope.from_iterable(data, label=Path(path).stem)
    if not isinstance(data, dict):
        raise ConfigError("scope document must be a mapping or a list of hosts")
    # Accept either a bare scope document or a full engagement file that nests
    # the scope under a "scope" key.
    nested = data.get("scope")
    if isinstance(nested, dict):
        return Scope.from_dict(nested)
    if isinstance(nested, list):
        return Scope.from_iterable(nested, label=Path(path).stem)
    return Scope.from_dict(data)


DEFAULT_ENGAGEMENT: dict[str, Any] = {
    "name": "example-engagement",
    "client": "Example Corp",
    "authorisation_reference": "PO-2026-001",
    "scope": {
        "label": "example",
        "in_scope": ["example.com", "*.example.com"],
        "out_of_scope": ["billing.example.com"],
    },
    "modules": ["subdomains", "portscan", "techdetect", "http-headers", "tls-audit"],
    "metadata": {"rate_limit": 5, "concurrency": 10},
}
