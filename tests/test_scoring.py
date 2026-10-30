"""CVSS and engagement-risk scoring tests, checked against known references."""

import math

import pytest

from vanta.core.models import Confidence, Finding, Severity
from vanta.core.scoring import aggregate_risk, cvss_base_score


@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
    ],
)
def test_cvss_base_scores(vector, expected):
    assert cvss_base_score(vector) == pytest.approx(expected, abs=0.05)


def test_cvss_rejects_malformed_vector():
    with pytest.raises(ValueError):
        cvss_base_score("not-a-vector")


def test_severity_mapping():
    assert Severity.from_cvss(0.0) is Severity.INFO
    assert Severity.from_cvss(3.1) is Severity.LOW
    assert Severity.from_cvss(5.5) is Severity.MEDIUM
    assert Severity.from_cvss(8.0) is Severity.HIGH
    assert Severity.from_cvss(9.9) is Severity.CRITICAL


def _f(sev, conf=Confidence.CONFIRMED, score=None):
    return Finding(title="t", module="m", target="h", severity=sev, confidence=conf, cvss_score=score)


def test_aggregate_risk_is_bounded_and_ordered():
    empty = aggregate_risk([])
    assert empty.score == 0.0
    assert 0 <= empty.score <= 100

    low = aggregate_risk([_f(Severity.LOW)])
    high = aggregate_risk([_f(Severity.CRITICAL), _f(Severity.HIGH)])
    assert low.score < high.score <= 100


def test_confidence_weighs_the_score():
    confirmed = aggregate_risk([_f(Severity.CRITICAL, Confidence.CONFIRMED)])
    tentative = aggregate_risk([_f(Severity.CRITICAL, Confidence.TENTATIVE)])
    assert tentative.score < confirmed.score


def test_grade_bands():
    assert aggregate_risk([]).grade == "A"
    many = [_f(Severity.CRITICAL) for _ in range(20)]
    assert aggregate_risk(many).grade == "F"
