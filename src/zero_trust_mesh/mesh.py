"""End-to-end request evaluation for the mesh.

:class:`MeshController` is the composition root. It owns the identity provider,
the workload CA, the trust engine, the policy decision point, and the session
store, and exposes a single :meth:`MeshController.evaluate` method that walks a
request through the full Zero Trust path:

    authenticate (mTLS + token + binding)
        -> score trust (identity + device + network + behavior)
        -> decide (policy)
        -> continuously verify (session state)

Because the whole path runs on every request, a session can lose access
mid-flight when a signal changes, which is the property the mesh exists to
demonstrate.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .ca import IssuedIdentity, WorkloadCA
from .identity import IdentityProvider
from .models import (
    AccessRequest,
    AssuranceLevel,
    Decision,
    DecisionEffect,
    DevicePosture,
    Mesh,
    PolicySet,
    SignalCategory,
    TrustAssessment,
    TrustFactor,
)
from .pdp import PolicyDecisionPoint
from .pep import PolicyEnforcementPoint
from .session import Session, SessionStore
from .trust import TrustEngine, TrustInputs


@dataclass(frozen=True)
class RequestContext:
    """Authentication and posture context accompanying an access request.

    When ``token`` is set the enforcement point verifies it (and the optional
    mTLS certificate) and the verified claims override ``assurance``/``amr``.
    When it is not, the declared values are used directly; that path is for
    synthetic fixtures and is clearly not a cryptographic authentication.
    """

    assurance: AssuranceLevel = AssuranceLevel.MULTI_FACTOR
    amr: tuple[str, ...] = ("pwd", "otp")
    posture: DevicePosture | None = None
    new_device: bool = False
    token: str | None = None
    certificate_der: bytes | None = None


def _fail_closed_trust(assurance: AssuranceLevel, reason: str) -> TrustAssessment:
    return TrustAssessment(
        score=0.0,
        assurance=assurance,
        factors=(
            TrustFactor(
                category=SignalCategory.IDENTITY,
                name="fail_closed",
                contribution=0.0,
                detail=reason,
            ),
        ),
        fail_closed=True,
    )


class MeshController:
    """Owns mesh state and evaluates access requests end to end."""

    def __init__(
        self,
        mesh: Mesh,
        policy_set: PolicySet,
        *,
        idp: IdentityProvider | None = None,
        ca: WorkloadCA | None = None,
        clock: Any = time.time,
    ) -> None:
        self.mesh = mesh
        self.policy_set = policy_set
        self.idp = idp or IdentityProvider()
        self.ca = ca or WorkloadCA(trust_domain=mesh.trust_domain)
        self.trust_engine = TrustEngine()
        self.pdp = PolicyDecisionPoint(policy_set)
        self.pep = PolicyEnforcementPoint(self.idp, self.ca)
        self.sessions = SessionStore()
        self._clock = clock
        self._workload_identities: dict[str, IssuedIdentity] = {}

    @property
    def audience(self) -> str:
        return self.mesh.trust_domain

    def workload_identity(self, service: str) -> IssuedIdentity:
        """Return (issuing on first use) the mTLS identity for a service."""

        identity = self._workload_identities.get(service)
        if identity is None:
            identity = self.ca.issue(service)
            self._workload_identities[service] = identity
        return identity

    def mint_token(
        self,
        *,
        subject: str,
        device_id: str,
        workload_service: str = "workstation-agent",
        assurance: AssuranceLevel = AssuranceLevel.MULTI_FACTOR,
        amr: tuple[str, ...] = ("pwd", "otp"),
        ttl_seconds: int = 900,
    ) -> tuple[str, bytes]:
        """Mint a certificate-bound token and return ``(token, cert_der)``."""

        identity = self.workload_identity(workload_service)
        thumbprint = self.idp.certificate_thumbprint(identity.certificate_der)
        token = self.idp.issue(
            subject=subject,
            audience=self.audience,
            device_id=device_id,
            assurance=assurance,
            amr=amr,
            confirmation=thumbprint,
            ttl_seconds=ttl_seconds,
        )
        return token, identity.certificate_der

    def evaluate(self, request: AccessRequest, context: RequestContext | None = None) -> Decision:
        """Evaluate one request and record it on its session."""

        context = context or RequestContext()
        principal = self.mesh.principal(request.principal_id)
        device = self.mesh.device(request.device_id)
        resource = self.mesh.resource(request.resource_id)
        if principal is None or device is None or resource is None:
            missing = [
                name
                for name, value in (
                    ("principal", principal),
                    ("device", device),
                    ("resource", resource),
                )
                if value is None
            ]
            return Decision(
                effect=DecisionEffect.DENY,
                principal_id=request.principal_id,
                resource_id=request.resource_id,
                action=request.action,
                trust=_fail_closed_trust(
                    context.assurance, f"unknown {', '.join(missing)}; failing closed"
                ),
                reasons=(f"unresolved subject or object: {', '.join(missing)}",),
            )

        session = self.sessions.ensure(
            request.session_id,
            principal_id=principal.id,
            device_id=device.id,
            at_epoch=request.at_epoch,
        )

        assurance = context.assurance
        amr = context.amr
        if context.token is not None:
            auth = self.pep.authenticate(
                token=context.token,
                audience=self.audience,
                certificate_der=context.certificate_der,
            )
            if not auth.authenticated:
                return self._deny_and_record(
                    session,
                    request,
                    _fail_closed_trust(assurance, "; ".join(auth.failures)),
                    "authentication failed",
                )
            if auth.subject != principal.id or auth.device_id != device.id:
                return self._deny_and_record(
                    session,
                    request,
                    _fail_closed_trust(assurance, "token subject/device does not match request"),
                    "token does not match the claimed principal or device",
                )
            assurance = auth.assurance or assurance
            amr = auth.amr or amr

        posture = context.posture or device.posture
        new_device = context.new_device or device.id not in session.known_devices
        inputs = TrustInputs(
            assurance=assurance,
            posture=posture,
            network=request.network,
            amr=amr,
            session_age_seconds=session.age_seconds(request.at_epoch),
            seconds_since_last_request=session.seconds_since_last(request.at_epoch),
            prior_country=session.last_country,
            new_device=new_device,
        )
        trust = self.trust_engine.assess(inputs)

        if session.state.value == "revoked":
            decision = Decision(
                effect=DecisionEffect.DENY,
                principal_id=principal.id,
                resource_id=resource.id,
                action=request.action,
                trust=trust,
                reasons=("session was previously revoked; re-authentication required",),
            )
        else:
            decision = self.pdp.authorize(
                principal=principal,
                resource=resource,
                action=request.action,
                network=request.network,
                trust=trust,
                managed_device=posture.managed,
            )

        self.sessions.record(
            session,
            decision=decision,
            at_epoch=request.at_epoch,
            resource_id=resource.id,
            action=request.action,
        )
        session.last_country = request.network.country
        session.known_devices.add(device.id)
        return decision

    def _deny_and_record(
        self, session: Session, request: AccessRequest, trust: TrustAssessment, reason: str
    ) -> Decision:
        decision = Decision(
            effect=DecisionEffect.DENY,
            principal_id=request.principal_id,
            resource_id=request.resource_id,
            action=request.action,
            trust=trust,
            reasons=(reason,),
        )
        self.sessions.record(
            session,
            decision=decision,
            at_epoch=request.at_epoch,
            resource_id=request.resource_id,
            action=request.action,
        )
        return decision


@dataclass
class MeshBuild:
    """Convenience bundle returned by :func:`build_controller`."""

    controller: MeshController
    mesh: Mesh
    policy_set: PolicySet
    extras: dict[str, object] = field(default_factory=dict)


def build_controller(mesh: Mesh, policy_set: PolicySet, **kwargs: Any) -> MeshController:
    return MeshController(mesh, policy_set, **kwargs)
