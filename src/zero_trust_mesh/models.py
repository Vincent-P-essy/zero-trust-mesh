"""Typed domain model for the Zero Trust mesh.

Every model is frozen and rejects unknown fields. Trust and policy decisions
carry the factors and rule that justified them so a reviewer can audit any
outcome without rerunning the engine.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TypeAlias

from pydantic import BaseModel, ConfigDict, Field, model_validator

Scalar: TypeAlias = str | int | float | bool | None

MAX_PRINCIPALS = 2_000
MAX_DEVICES = 5_000
MAX_RESOURCES = 5_000
MAX_SERVICES = 1_000
MAX_POLICIES = 2_000
MAX_SELECTOR_ITEMS = 256
IDENTIFIER = r"^[a-z0-9][a-z0-9_.:/-]{0,127}$"


class PrincipalKind(StrEnum):
    """A human operator or a non-human workload identity."""

    HUMAN = "human"
    WORKLOAD = "workload"
    SERVICE = "service"


class Sensitivity(StrEnum):
    """Data classification of a protected resource, ordered low to high."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class AssuranceLevel(StrEnum):
    """Coarse authentication assurance level, aligned with NIST SP 800-63 AAL."""

    NONE = "aal0"
    SINGLE_FACTOR = "aal1"
    MULTI_FACTOR = "aal2"
    HARDWARE = "aal3"


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class DecisionEffect(StrEnum):
    """Terminal decision returned by the policy decision point."""

    PERMIT = "permit"
    DENY = "deny"
    STEP_UP = "step_up"


class SessionState(StrEnum):
    ACTIVE = "active"
    STEP_UP_REQUIRED = "step_up_required"
    REVOKED = "revoked"
    EXPIRED = "expired"


class SignalCategory(StrEnum):
    """Groups the inputs that continuous verification combines into trust."""

    IDENTITY = "identity"
    DEVICE = "device"
    NETWORK = "network"
    BEHAVIOR = "behavior"
    SESSION = "session"


SENSITIVITY_RANK: dict[Sensitivity, int] = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.INTERNAL: 1,
    Sensitivity.CONFIDENTIAL: 2,
    Sensitivity.RESTRICTED: 3,
}

ASSURANCE_RANK: dict[AssuranceLevel, int] = {
    AssuranceLevel.NONE: 0,
    AssuranceLevel.SINGLE_FACTOR: 1,
    AssuranceLevel.MULTI_FACTOR: 2,
    AssuranceLevel.HARDWARE: 3,
}


class Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DevicePosture(Frozen):
    """Attested security posture of an endpoint.

    Fields describe controls a mobile-device-management or endpoint agent can
    report. ``attestation_age_seconds`` records how stale the attestation is;
    the scorer treats an old attestation as an unknown and fails closed.
    """

    managed: bool = False
    disk_encrypted: bool = False
    screen_lock: bool = False
    firewall: bool = False
    edr_active: bool = False
    secure_boot: bool = False
    os_patch_age_days: int = Field(default=999, ge=0, le=3650)
    jailbroken: bool = False
    attestation_age_seconds: int = Field(default=0, ge=0, le=2_592_000)


class Device(Frozen):
    id: str = Field(pattern=IDENTIFIER)
    owner: str = Field(pattern=IDENTIFIER)
    label: str = Field(default="", max_length=120)
    posture: DevicePosture = DevicePosture()


class NetworkContext(Frozen):
    """Where a request originates from, as seen by the enforcement point."""

    ip: str = Field(default="0.0.0.0", max_length=45)  # noqa: S104 - synthetic placeholder
    country: str = Field(default="ZZ", pattern=r"^[A-Z]{2}$")
    asn: int = Field(default=0, ge=0, le=4_294_967_295)
    corporate: bool = False
    tor_exit: bool = False
    anonymizing_vpn: bool = False


class WorkloadIdentity(Frozen):
    """SPIFFE-style identity presented over mTLS by a mesh workload."""

    spiffe_id: str = Field(pattern=r"^spiffe://[a-z0-9.-]+(/[A-Za-z0-9_.-]+)+$", max_length=256)
    service: str = Field(pattern=IDENTIFIER)


class Principal(Frozen):
    id: str = Field(pattern=IDENTIFIER)
    kind: PrincipalKind = PrincipalKind.HUMAN
    display_name: str = Field(default="", max_length=120)
    roles: tuple[str, ...] = Field(default=(), max_length=MAX_SELECTOR_ITEMS)
    groups: tuple[str, ...] = Field(default=(), max_length=MAX_SELECTOR_ITEMS)


class Resource(Frozen):
    id: str = Field(pattern=IDENTIFIER)
    service: str = Field(pattern=IDENTIFIER)
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    description: str = Field(default="", max_length=200)


class Service(Frozen):
    """A workload in the mesh that owns resources and enforces policy."""

    id: str = Field(pattern=IDENTIFIER)
    namespace: str = Field(default="default", pattern=IDENTIFIER)
    description: str = Field(default="", max_length=200)


class Credential(Frozen):
    """Bearer token presented with a request, already parsed by the caller."""

    token: str = Field(min_length=1, max_length=8192)
    binding: str | None = Field(default=None, max_length=128)


class AccessRequest(Frozen):
    """A single attempt to perform an action on a resource within a session."""

    session_id: str = Field(pattern=IDENTIFIER)
    principal_id: str = Field(pattern=IDENTIFIER)
    device_id: str = Field(pattern=IDENTIFIER)
    resource_id: str = Field(pattern=IDENTIFIER)
    action: str = Field(pattern=r"^[a-z][a-z0-9_.:-]{0,63}$")
    network: NetworkContext = NetworkContext()
    workload: WorkloadIdentity | None = None
    credential: Credential | None = None
    at_epoch: float = Field(default=0.0, ge=0)


class TrustFactor(Frozen):
    """One additive contribution to a trust score, retained as evidence."""

    category: SignalCategory
    name: str = Field(max_length=64)
    contribution: float = Field(ge=-100, le=100)
    detail: str = Field(max_length=200)


class TrustAssessment(Frozen):
    """A trust score in ``[0, 100]`` with the factors that produced it."""

    score: float = Field(ge=0, le=100)
    assurance: AssuranceLevel
    factors: tuple[TrustFactor, ...]
    fail_closed: bool = False

    @property
    def positive(self) -> tuple[TrustFactor, ...]:
        return tuple(f for f in self.factors if f.contribution >= 0)

    @property
    def penalties(self) -> tuple[TrustFactor, ...]:
        return tuple(f for f in self.factors if f.contribution < 0)


class Selector(Frozen):
    """Matches principals, resources, and actions for a policy rule."""

    principals: tuple[str, ...] = Field(default=(), max_length=MAX_SELECTOR_ITEMS)
    roles: tuple[str, ...] = Field(default=(), max_length=MAX_SELECTOR_ITEMS)
    groups: tuple[str, ...] = Field(default=(), max_length=MAX_SELECTOR_ITEMS)
    services: tuple[str, ...] = Field(default=(), max_length=MAX_SELECTOR_ITEMS)
    resources: tuple[str, ...] = Field(default=(), max_length=MAX_SELECTOR_ITEMS)
    sensitivities: tuple[Sensitivity, ...] = Field(default=(), max_length=8)
    actions: tuple[str, ...] = Field(default=("*",), max_length=MAX_SELECTOR_ITEMS)


class PolicyRule(Frozen):
    """A single access rule.

    ``effect=deny`` rules are evaluated first and win over any permit, matching
    the deny-override principle used by mainstream authorization engines.
    """

    id: str = Field(pattern=IDENTIFIER)
    description: str = Field(default="", max_length=200)
    effect: Effect = Effect.ALLOW
    match: Selector = Selector()
    min_trust: float = Field(default=0.0, ge=0, le=100)
    min_assurance: AssuranceLevel = AssuranceLevel.NONE
    require_managed_device: bool = False
    require_corporate_network: bool = False
    forbid_anonymized_network: bool = False
    step_up_below_trust: float | None = Field(default=None, ge=0, le=100)

    @model_validator(mode="after")
    def _step_up_consistent(self) -> PolicyRule:
        if self.step_up_below_trust is not None and self.step_up_below_trust < self.min_trust:
            raise ValueError("step_up_below_trust must be >= min_trust")
        return self


class PolicySet(Frozen):
    name: str = Field(default="mesh", max_length=80)
    default_effect: Effect = Effect.DENY
    rules: tuple[PolicyRule, ...] = Field(default=(), max_length=MAX_POLICIES)


class Obligation(Frozen):
    """An action the enforcement point must take before or instead of allowing."""

    kind: str = Field(max_length=48)
    detail: str = Field(max_length=200)


class Decision(Frozen):
    """The authoritative output of the policy decision point for one request."""

    effect: DecisionEffect
    principal_id: str
    resource_id: str
    action: str
    trust: TrustAssessment
    matched_rule: str | None = None
    reasons: tuple[str, ...] = ()
    obligations: tuple[Obligation, ...] = ()

    @property
    def permitted(self) -> bool:
        return self.effect is DecisionEffect.PERMIT


class VerificationEvent(Frozen):
    """One entry in a session's continuous-verification timeline."""

    sequence: int = Field(ge=0)
    at_epoch: float = Field(ge=0)
    resource_id: str
    action: str
    effect: DecisionEffect
    trust_score: float = Field(ge=0, le=100)
    state: SessionState
    reason: str = Field(max_length=200)


class SessionSummary(Frozen):
    session_id: str
    principal_id: str
    device_id: str
    state: SessionState
    events: tuple[VerificationEvent, ...]

    @property
    def permitted_count(self) -> int:
        return sum(1 for e in self.events if e.effect is DecisionEffect.PERMIT)

    @property
    def denied_count(self) -> int:
        return sum(1 for e in self.events if e.effect is DecisionEffect.DENY)


class Mesh(Frozen):
    """The synthetic environment: principals, devices, resources, and services."""

    name: str = Field(default="synthetic-mesh", max_length=80)
    trust_domain: str = Field(default="mesh.internal", pattern=r"^[a-z0-9.-]+$")
    principals: tuple[Principal, ...] = Field(default=(), max_length=MAX_PRINCIPALS)
    devices: tuple[Device, ...] = Field(default=(), max_length=MAX_DEVICES)
    resources: tuple[Resource, ...] = Field(default=(), max_length=MAX_RESOURCES)
    services: tuple[Service, ...] = Field(default=(), max_length=MAX_SERVICES)

    @model_validator(mode="after")
    def _unique_ids(self) -> Mesh:
        for label, items in (
            ("principal", self.principals),
            ("device", self.devices),
            ("resource", self.resources),
            ("service", self.services),
        ):
            ids = [item.id for item in items]
            if len(ids) != len(set(ids)):
                raise ValueError(f"duplicate {label} id")
        return self

    def principal(self, principal_id: str) -> Principal | None:
        return next((p for p in self.principals if p.id == principal_id), None)

    def device(self, device_id: str) -> Device | None:
        return next((d for d in self.devices if d.id == device_id), None)

    def resource(self, resource_id: str) -> Resource | None:
        return next((r for r in self.resources if r.id == resource_id), None)
