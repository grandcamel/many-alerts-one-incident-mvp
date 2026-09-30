"""Mandatory route failure and optional Memory degradation are distinct."""

from dataclasses import FrozenInstanceError

import pytest

from grafana_jsm_sandbox.forwarder_services import SERVICE_PROFILES, classify_readiness


def test_profiles_pin_distinct_loopback_listeners_and_authentication_schemes():
    expected = {
        "jira": (17441, "Basic"), "confluence": (17442, "Basic"),
        "grafana": (17443, "Bearer"), "kubernetes": (17444, "Bearer"),
        "anthropic": (17445, "Bearer"),
    }
    assert set(SERVICE_PROFILES) == set(expected)
    for name, (port, scheme) in expected.items():
        profile = SERVICE_PROFILES[name]
        assert (profile.port, profile.sentinel_scheme) == (port, scheme)
        assert profile.bind_host == "127.0.0.1"
        assert profile.server_name == f"forwarder-{name}.maoi.local"
    with pytest.raises(TypeError):
        SERVICE_PROFILES["other"] = SERVICE_PROFILES["jira"]
    with pytest.raises(FrozenInstanceError):
        SERVICE_PROFILES["jira"].port = 80


def test_missing_route_facts_hold_all_mandatory_services():
    result = classify_readiness({})
    assert result.mandatory_ready is False
    assert result.unavailable_mandatory == ("jira", "grafana", "kubernetes", "anthropic")
    assert result.degraded_optional == ("confluence",)


@pytest.mark.parametrize("optional", [None, False, True])
def test_confluence_absence_or_failure_does_not_hold_mandatory_routes(optional):
    facts = {name: True for name in ("jira", "grafana", "kubernetes", "anthropic")}
    if optional is not None:
        facts["confluence"] = optional
    result = classify_readiness(facts)
    assert result.mandatory_ready is True
    assert result.unavailable_mandatory == ()
    assert result.degraded_optional == (() if optional is True else ("confluence",))


@pytest.mark.parametrize("service", ["jira", "grafana", "kubernetes", "anthropic"])
def test_each_mandatory_route_independently_holds_readiness(service):
    facts = dict.fromkeys(SERVICE_PROFILES, True)
    facts[service] = False
    result = classify_readiness(facts)
    assert result.mandatory_ready is False
    assert result.unavailable_mandatory == (service,)
    assert result.degraded_optional == ()


@pytest.mark.parametrize("facts", [{"jira": 1}, {"jira": None}, {"jira": "ready"}, []])
def test_readiness_requires_explicit_typed_facts(facts):
    with pytest.raises(TypeError):
        classify_readiness(facts)


@pytest.mark.parametrize("name", ["Jira", "grafana/eyes", "other", 1])
def test_unknown_service_cannot_expand_fixed_profiles(name):
    with pytest.raises(ValueError):
        classify_readiness({name: True})
