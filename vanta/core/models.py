"""Domain models for VANTA.

Everything the engine passes around is a small, serialisable dataclass. Keeping
the models dumb (no I/O, no logic) makes the framework easy to test and means a
finding produced by a module is identical whether it is rendered to Markdown,
JSON, or HTML.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Ordered severity levels used across findings and reports."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER[self]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Map a CVSS v3.1 base score to a qualitative severity band."""
        if score <= 0:
            return cls.INFO
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

SEVERITY_COLOURS = {
    Severity.INFO: "blue",
    Severity.LOW: "green",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "magenta",
}


class Confidence(str, Enum):
    """How sure are we that a finding is real (drives false-positive triage)."""

    TENTATIVE = "tentative"
    FIRM = "firm"
    CONFIRMED = "confirmed"


@dataclass
class Evidence:
    """A single artefact proving a finding (HTTP response, banner, cert, ...)."""

    kind: str
    summary: str
    sha256: str = ""
    path: Optional[str] = None
    captured_at: float = field(default_factory=time.time)

    @staticmethod
    def hash_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


@dataclass
class Target:
    """One host/service that modules operate against."""

    host: str
    scheme: str = "https"
    port: Optional[int] = None
    path: str = "/"

    @property
    def base_url(self) -> str:
        netloc = self.host
        if self.port and self.port not in (80, 443):
            netloc = f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}"

    @property
    def url(self) -> str:
        return self.base_url.rstrip("/") + "/" + self.path.lstrip("/")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A single observation a module wants to report.

    ``attck`` is a list of MITRE ATT&CK technique IDs (e.g. ``T1595``) and
    ``leads_to`` points at the finding id of the next step in an attack path,
    which is what lets the engine assemble a kill chain rather than a flat list.
    """

    title: str
    module: str
    target: str
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.FIRM
    description: str = ""
    impact: str = ""
    remediation: str = ""
    category: str = "general"
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    attck: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    leads_to: Optional[str] = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


@dataclass
class ModuleResult:
    """What a module hands back to the engine."""

    module: str
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None
    duration: float = 0.0
    skipped: bool = False
    skip_reason: Optional[str] = None


@dataclass
class Engagement:
    """The top-level record for one authorised piece of work."""

    name: str
    client: str = ""
    authorisation_reference: str = ""
    scope: dict[str, Any] = field(default_factory=dict)
    modules: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
