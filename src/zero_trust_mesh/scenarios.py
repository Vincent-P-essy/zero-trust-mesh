"""Canned continuous-verification scenarios over the synthetic mesh.

Each scenario is a short sequence of requests within one session, chosen to
demonstrate a specific Zero Trust property: a soft-trust step-up, a mid-session
posture collapse that revokes access, impossible travel, live token revocation,
and explicit deny-override. The expected effect of every step is declared inline
and forms the ground truth the benchmark verifies against, so a regression in
the engine is caught as a changed outcome rather than a changed number.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .mesh import MeshController, RequestContext
from .models import (
    AccessRequest,
    AssuranceLevel,
    Decision,
    DecisionEffect,
    DevicePosture,
    NetworkContext,
    SessionState,
)

# Reusable network origins.
CORP_FR = NetworkContext(ip="10.20.0.5", country="FR", asn=64500, corporate=True)
HOME_FR = NetworkContext(ip="88.120.0.5", country="FR", asn=3215)
FOREIGN_RU = NetworkContext(ip="95.140.0.5", country="RU", asn=12389)
TOR_EXIT = NetworkContext(ip="185.220.0.5", country="NL", asn=0, tor_exit=True)

STRONG_AMR = ("pwd", "webauthn")
MFA_AMR = ("pwd", "otp")

# A posture whose attestation has gone stale mid-session (the endpoint agent
# stopped reporting), which the scorer treats as unknown and fails closed.
STALE_POSTURE = DevicePosture(
    managed=True,
    disk_encrypted=True,
    screen_lock=True,
    firewall=True,
    edr_active=True,
    secure_boot=True,
    os_patch_age_days=3,
    attestation_age_seconds=50_000,
)


@dataclass(frozen=True)
class ScenarioStep:
    resource_id: str
    expect: DecisionEffect
    action: str = "read"
    at_epoch: float = 0.0
    assurance: AssuranceLevel = AssuranceLevel.MULTI_FACTOR
    amr: tuple[str, ...] = MFA_AMR
    network: NetworkContext = CORP_FR
    posture_override: DevicePosture | None = None
    new_device: bool = False
    use_token: bool = False
    revoke_token_first: bool = False


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    principal_id: str
    device_id: str
    steps: tuple[ScenarioStep, ...]
    expect_final_state: SessionState


@dataclass
class StepOutcome:
    step: ScenarioStep
    decision: Decision
    matched: bool


@dataclass
class ScenarioResult:
    scenario: Scenario
    outcomes: list[StepOutcome] = field(default_factory=list)
    final_state: SessionState = SessionState.ACTIVE

    @property
    def matched(self) -> bool:
        return all(o.matched for o in self.outcomes) and (
            self.final_state is self.scenario.expect_final_state
        )


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        name="baseline-permit",
        description="Compliant SRE on a managed laptop reaches the payments ledger.",
        principal_id="alice",
        device_id="laptop-alice",
        steps=(ScenarioStep("payments-db", DecisionEffect.PERMIT, amr=STRONG_AMR),),
        expect_final_state=SessionState.ACTIVE,
    ),
    Scenario(
        name="step-up-required",
        description="Finance analyst with soft trust is asked to step up for PII.",
        principal_id="bob",
        device_id="laptop-bob",
        steps=(ScenarioStep("customer-pii", DecisionEffect.STEP_UP),),
        expect_final_state=SessionState.STEP_UP_REQUIRED,
    ),
    Scenario(
        name="unmanaged-audit-deny",
        description="Auditor on an unmanaged device is denied the audit store.",
        principal_id="vendor-auditor",
        device_id="byod-vendor",
        steps=(ScenarioStep("audit-logs", DecisionEffect.DENY, network=HOME_FR),),
        expect_final_state=SessionState.ACTIVE,
    ),
    Scenario(
        name="external-restricted-deny",
        description="Deny-override stops an external principal reaching restricted data.",
        principal_id="vendor-auditor",
        device_id="byod-vendor",
        steps=(ScenarioStep("payments-db", DecisionEffect.DENY, network=HOME_FR),),
        expect_final_state=SessionState.ACTIVE,
    ),
    Scenario(
        name="anonymized-network-deny",
        description="Access from a Tor exit is refused for the payments ledger.",
        principal_id="alice",
        device_id="laptop-alice",
        steps=(ScenarioStep("payments-db", DecisionEffect.DENY, amr=STRONG_AMR, network=TOR_EXIT),),
        expect_final_state=SessionState.ACTIVE,
    ),
    Scenario(
        name="impossible-travel-deny",
        description="A session that jumps countries in minutes loses access.",
        principal_id="alice",
        device_id="laptop-alice",
        steps=(
            ScenarioStep("payments-db", DecisionEffect.PERMIT, amr=STRONG_AMR, network=CORP_FR),
            ScenarioStep(
                "payments-db",
                DecisionEffect.DENY,
                at_epoch=600,
                amr=STRONG_AMR,
                network=FOREIGN_RU,
            ),
        ),
        expect_final_state=SessionState.ACTIVE,
    ),
    Scenario(
        name="posture-drop-revoke",
        description="A device that stops attesting mid-session is revoked and stays revoked.",
        principal_id="alice",
        device_id="laptop-alice",
        steps=(
            ScenarioStep("payments-db", DecisionEffect.PERMIT, amr=STRONG_AMR),
            ScenarioStep(
                "payments-db",
                DecisionEffect.DENY,
                at_epoch=600,
                amr=STRONG_AMR,
                posture_override=STALE_POSTURE,
            ),
            ScenarioStep("payments-db", DecisionEffect.DENY, at_epoch=1200, amr=STRONG_AMR),
        ),
        expect_final_state=SessionState.REVOKED,
    ),
    Scenario(
        name="token-revoked-mid-session",
        description="Revoking the bearer token mid-session immediately blocks the next call.",
        principal_id="alice",
        device_id="laptop-alice",
        steps=(
            ScenarioStep("payments-db", DecisionEffect.PERMIT, use_token=True),
            ScenarioStep(
                "payments-db",
                DecisionEffect.DENY,
                at_epoch=300,
                use_token=True,
                revoke_token_first=True,
            ),
        ),
        expect_final_state=SessionState.REVOKED,
    ),
    Scenario(
        name="public-low-trust-permit",
        description="A low-trust device still reaches public resources, and only those.",
        principal_id="vendor-auditor",
        device_id="byod-vendor",
        steps=(ScenarioStep("status-page", DecisionEffect.PERMIT, network=HOME_FR),),
        expect_final_state=SessionState.ACTIVE,
    ),
)


def _session_id(name: str, suffix: str) -> str:
    return f"{name}-{suffix}" if suffix else name


def run_scenario(
    controller: MeshController, scenario: Scenario, *, suffix: str = ""
) -> ScenarioResult:
    """Execute one scenario against ``controller`` and compare to expectations."""

    result = ScenarioResult(scenario=scenario)
    session_id = _session_id(scenario.name, suffix)
    token: str | None = None
    certificate: bytes | None = None

    for step in scenario.steps:
        if step.use_token:
            if token is None:
                token, certificate = controller.mint_token(
                    subject=scenario.principal_id,
                    device_id=scenario.device_id,
                    assurance=step.assurance,
                    amr=step.amr,
                )
            if step.revoke_token_first and token is not None:
                claims = controller.idp.introspect(token, audience=controller.audience).claims
                controller.idp.revoke(str(claims["jti"]))
            context = RequestContext(
                token=token,
                certificate_der=certificate,
                posture=step.posture_override,
                new_device=step.new_device,
            )
        else:
            context = RequestContext(
                assurance=step.assurance,
                amr=step.amr,
                posture=step.posture_override,
                new_device=step.new_device,
            )

        request = AccessRequest(
            session_id=session_id,
            principal_id=scenario.principal_id,
            device_id=scenario.device_id,
            resource_id=step.resource_id,
            action=step.action,
            network=step.network,
            at_epoch=step.at_epoch,
        )
        decision = controller.evaluate(request, context)
        result.outcomes.append(
            StepOutcome(step=step, decision=decision, matched=decision.effect is step.expect)
        )

    session = controller.sessions.get(session_id)
    result.final_state = session.state if session is not None else SessionState.EXPIRED
    return result


def run_all(controller: MeshController, *, suffix: str = "") -> list[ScenarioResult]:
    return [run_scenario(controller, scenario, suffix=suffix) for scenario in SCENARIOS]


def ground_truth() -> dict[str, dict[str, object]]:
    """Return the declared expected outcomes as a serializable mapping."""

    return {
        scenario.name: {
            "effects": [step.expect.value for step in scenario.steps],
            "final_state": scenario.expect_final_state.value,
        }
        for scenario in SCENARIOS
    }
