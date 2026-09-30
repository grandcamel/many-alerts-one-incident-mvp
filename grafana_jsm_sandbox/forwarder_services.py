"""Fixed Forwarder listener profiles and one component of admission readiness.

These nonsecret constants do not configure upstream origins or grant request
authority. Transport, request policy, authenticated control and OS isolation
must establish their own evidence before a native Run can be admitted.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class ServiceProfile:
    name: str
    port: int
    mandatory: bool
    sentinel_scheme: str

    @property
    def bind_host(self) -> str:
        return "127.0.0.1"

    @property
    def server_name(self) -> str:
        return f"forwarder-{self.name}.maoi.local"


SERVICE_PROFILES: Mapping[str, ServiceProfile] = MappingProxyType({
    "jira": ServiceProfile("jira", 17441, True, "Basic"),
    "confluence": ServiceProfile("confluence", 17442, False, "Basic"),
    "grafana": ServiceProfile("grafana", 17443, True, "Bearer"),
    "kubernetes": ServiceProfile("kubernetes", 17444, True, "Bearer"),
    "anthropic": ServiceProfile("anthropic", 17445, True, "Bearer"),
})


@dataclass(frozen=True)
class RouteReadiness:
    mandatory_ready: bool
    unavailable_mandatory: tuple[str, ...]
    degraded_optional: tuple[str, ...]


def classify_readiness(route_facts: Mapping[str, bool]) -> RouteReadiness:
    """Classify trusted per-route facts; missing facts never imply readiness.

    This result does not attest the facts, create a lease, authorize dispatch,
    or replace the Receiver's recovery, accounting and native-launch gates.
    """
    if not isinstance(route_facts, Mapping):
        raise TypeError("route readiness requires a mapping")
    facts = dict(route_facts)
    if any(type(name) is not str or name not in SERVICE_PROFILES for name in facts):
        raise ValueError("unknown readiness service")
    if any(type(ready) is not bool for ready in facts.values()):
        raise TypeError("route readiness requires explicit booleans")
    unavailable = tuple(name for name, profile in SERVICE_PROFILES.items()
                        if profile.mandatory and not facts.get(name, False))
    degraded = tuple(name for name, profile in SERVICE_PROFILES.items()
                     if not profile.mandatory and not facts.get(name, False))
    return RouteReadiness(not unavailable, unavailable, degraded)
