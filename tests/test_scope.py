"""Scope guard tests - the safety-critical component."""

import pytest

from vanta.core.scope import Scope, ScopeViolation


def test_exact_host_and_subdomains_are_allowed():
    scope = Scope(in_scope=["example.com"])
    assert scope.is_in_scope("example.com")
    assert scope.is_in_scope("api.example.com")
    assert scope.is_in_scope("deep.api.example.com")


def test_bare_domain_does_not_match_lookalikes():
    scope = Scope(in_scope=["example.com"])
    assert not scope.is_in_scope("example.com.evil.net")
    assert not scope.is_in_scope("notexample.com")


def test_wildcard_matches_subdomains_but_not_apex():
    scope = Scope(in_scope=["*.example.com"])
    assert scope.is_in_scope("api.example.com")
    assert not scope.is_in_scope("example.com")


def test_exclusions_always_win():
    scope = Scope(
        in_scope=["*.example.com"],
        out_of_scope=["billing.example.com"],
    )
    assert scope.is_in_scope("api.example.com")
    assert not scope.is_in_scope("billing.example.com")


def test_cidr_ranges():
    scope = Scope(in_scope=["10.0.0.0/24", "192.168.1.0/24"])
    assert scope.is_in_scope("10.0.0.5")
    assert scope.is_in_scope("192.168.1.255")
    assert not scope.is_in_scope("10.0.1.5")
    assert not scope.is_in_scope("8.8.8.8")


def test_urls_are_normalised_to_hostnames():
    scope = Scope(in_scope=["https://api.example.com/v1/users"])
    assert scope.is_in_scope("api.example.com")


def test_default_deny_and_default_allow():
    deny = Scope(in_scope=["a.com"])
    assert not deny.is_in_scope("b.com")

    allow = Scope(in_scope=[], default_allow=True)
    assert allow.is_in_scope("anything.example")


def test_assert_raises_outside_scope():
    scope = Scope(in_scope=["example.com"])
    scope.assert_in_scope("api.example.com")
    with pytest.raises(ScopeViolation):
        scope.assert_in_scope("evil.example.net")


def test_case_and_trailing_dot_insensitive():
    scope = Scope(in_scope=["Example.COM"])
    assert scope.is_in_scope("API.example.com.")
