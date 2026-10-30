"""Risk scoring: a faithful CVSS v3.1 base-score implementation plus an
engagement-level aggregate that blends severity, confidence and exposure.

The CVSS maths is implemented directly from the specification so the project
does not depend on a third-party library and so it can be explained in a
dissertation chapter line-by-line.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from vanta.core.models import Confidence, Severity

# -- CVSS v3.1 metric weights -------------------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_VECTOR_RE = re.compile(
    r"^CVSS:3\.[01]/AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/"
    r"UI:(?P<UI>[NR])/S:(?P<S>[UC])/C:(?P<C>[HLN])/I:(?P<I>[HLN])/A:(?P<A>[HLN])$"
)


def _roundup(value: float) -> float:
    """CVSS 'Roundup': round up to one decimal place (spec-defined)."""
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def cvss_base_score(vector: str) -> float:
    """Compute a CVSS v3.1 base score from a vector string.

    Raises ``ValueError`` on a malformed vector so callers notice bad data
    instead of silently reporting a wrong risk number.
    """
    m = _VECTOR_RE.match(vector.strip())
    if not m:
        raise ValueError(f"malformed CVSS v3.1 vector: {vector!r}")
    g = m.groupdict()
    scope_changed = g["S"] == "C"

    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[g["PR"]]

    iss = 1 - (
        (1 - _CIA[g["C"]]) * (1 - _CIA[g["I"]]) * (1 - _CIA[g["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * _AV[g["AV"]] * _AC[g["AC"]] * pr * _UI[g["UI"]]

    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)
    return _roundup(raw)


@dataclass
class RiskProfile:
    """Aggregated risk for a whole engagement."""

    score: float
    grade: str
    severity_counts: dict[str, int]
    confidence_counts: dict[str, int]
    top_findings: list[str]

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 2),
            "grade": self.grade,
            "severity_counts": self.severity_counts,
            "confidence_counts": self.confidence_counts,
            "top_findings": self.top_findings,
        }


_CONFIDENCE_MULTIPLIER = {
    Confidence.CONFIRMED: 1.0,
    Confidence.FIRM: 0.8,
    Confidence.TENTATIVE: 0.5,
}

_SEVERITY_POINTS = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 20.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
}


def _grade(score: float) -> str:
    if score >= 80:
        return "F"
    if score >= 60:
        return "E"
    if score >= 40:
        return "D"
    if score >= 25:
        return "C"
    if score >= 10:
        return "B"
    return "A"


def aggregate_risk(findings) -> RiskProfile:
    """Blend findings into a 0-100 engagement score.

    Uses a saturating curve so ~10 criticals do not blow past 100, and weighs
    each finding by confidence (a tentative critical is worth half of a
    confirmed one). This is deliberately simple and explainable, which matters
    more for a report than raw precision.
    """
    from vanta.core.models import Finding  # local import avoids a cycle

    score = 0.0
    sev_counts: dict[str, int] = {s.value: 0 for s in Severity}
    conf_counts: dict[str, int] = {c.value: 0 for c in Confidence}

    for f in findings:
        assert isinstance(f, Finding)
        sev_counts[f.severity.value] += 1
        conf_counts[f.confidence.value] += 1
        base = f.cvss_score if f.cvss_score is not None else _SEVERITY_POINTS[f.severity]
        score += base * _CONFIDENCE_MULTIPLIER[f.confidence]

    # Saturating transform keeps the score inside [0, 100].
    normalised = 100.0 * (1 - math.exp(-score / 120.0)) if score > 0 else 0.0

    ranked = sorted(
        findings,
        key=lambda f: (f.severity.rank, _CONFIDENCE_MULTIPLIER[f.confidence]),
        reverse=True,
    )
    top = [f.title for f in ranked[:5]]

    return RiskProfile(
        score=normalised,
        grade=_grade(normalised),
        severity_counts=sev_counts,
        confidence_counts=conf_counts,
        top_findings=top,
    )
