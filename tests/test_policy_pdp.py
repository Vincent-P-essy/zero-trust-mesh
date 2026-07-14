from __future__ import annotations

from zero_trust_mesh.models import (
    AssuranceLevel,
    Decision,
    DecisionEffect,
    Effect,
    NetworkContext,
    PolicyRule,
    PolicySet,
    Principal,
    Resource,
    Selector,
    Sensitivity,
    SessionState,
    TrustAssessment,
)
from zero_trust_mesh.pdp import PolicyDecisionPoint
from zero_trust_mesh.policy import selector_matches
from zero_trust_mesh.session import SessionStore

ALICE = Principal(id="alice", roles=("sre",), groups=("platform",))
PAYMENTS = Resource(id="payments-db", service="payments", sensitivity=Sensitivity.RESTRICTED)
CORP = NetworkContext(corporate=True)


def trust(
    score: float, *, assurance: AssuranceLevel = AssuranceLevel.MULTI_FACTOR, fail: bool = False
) -> TrustAssessment:
    return TrustAssessment(score=score, assurance=assurance, factors=(), fail_closed=fail)


def test_selector_matches_by_role_and_glob() -> None:
    selector = Selector(roles=("sre",), actions=("read*",))
    assert selector_matches(selector, principal=ALICE, resource=PAYMENTS, action="read")
    assert not selector_matches(
        Selector(roles=("analyst",)), principal=ALICE, resource=PAYMENTS, action="read"
    )
    assert not selector_matches(
        Selector(actions=("write",)), principal=ALICE, resource=PAYMENTS, action="read"
    )


def test_selector_matches_by_sensitivity_and_service() -> None:
    selector = Selector(sensitivities=(Sensitivity.RESTRICTED,), services=("payments",))
    assert selector_matches(selector, principal=ALICE, resource=PAYMENTS, action="read")


def _pdp(*rules: PolicyRule, default: Effect = Effect.DENY) -> PolicyDecisionPoint:
    return PolicyDecisionPoint(PolicySet(rules=rules, default_effect=default))


def test_default_deny_when_no_rule_matches() -> None:
    decision = _pdp().authorize(
        principal=ALICE,
        resource=PAYMENTS,
        action="read",
        network=CORP,
        trust=trust(99),
        managed_device=True,
    )
    assert decision.effect is DecisionEffect.DENY


def test_default_allow_configuration() -> None:
    decision = _pdp(default=Effect.ALLOW).authorize(
        principal=ALICE,
        resource=PAYMENTS,
        action="read",
        network=CORP,
        trust=trust(99),
        managed_device=True,
    )
    assert decision.effect is DecisionEffect.PERMIT


def test_permit_when_conditions_hold() -> None:
    rule = PolicyRule(id="allow", match=Selector(roles=("sre",)), min_trust=80)
    decision = _pdp(rule).authorize(
        principal=ALICE,
        resource=PAYMENTS,
        action="read",
        network=CORP,
        trust=trust(85),
        managed_device=True,
    )
    assert decision.effect is DecisionEffect.PERMIT
    assert decision.matched_rule == "allow"


def test_deny_override_wins() -> None:
    allow = PolicyRule(id="allow", match=Selector(roles=("sre",)), min_trust=0)
    deny = PolicyRule(
        id="deny", effect=Effect.DENY, match=Selector(sensitivities=(Sensitivity.RESTRICTED,))
    )
    decision = _pdp(allow, deny).authorize(
        principal=ALICE,
        resource=PAYMENTS,
        action="read",
        network=CORP,
        trust=trust(99),
        managed_device=True,
    )
    assert decision.effect is DecisionEffect.DENY
    assert decision.matched_rule == "deny"


def test_low_trust_is_denied() -> None:
    rule = PolicyRule(id="allow", match=Selector(roles=("sre",)), min_trust=80)
    decision = _pdp(rule).authorize(
        principal=ALICE,
        resource=PAYMENTS,
        action="read",
        network=CORP,
        trust=trust(50),
        managed_device=True,
    )
    assert decision.effect is DecisionEffect.DENY


def test_step_up_when_below_floor() -> None:
    rule = PolicyRule(
        id="allow", match=Selector(roles=("sre",)), min_trust=60, step_up_below_trust=90
    )
    decision = _pdp(rule).authorize(
        principal=ALICE,
        resource=PAYMENTS,
        action="read",
        network=CORP,
        trust=trust(50),
        managed_device=True,
    )
    assert decision.effect is DecisionEffect.STEP_UP
    assert decision.obligations[0].kind == "step_up_auth"


def test_step_up_between_floor_and_threshold() -> None:
    rule = PolicyRule(
        id="allow", match=Selector(roles=("sre",)), min_trust=60, step_up_below_trust=90
    )
    decision = _pdp(rule).authorize(
        principal=ALICE,
        resource=PAYMENTS,
        action="read",
        network=CORP,
        trust=trust(75),
        managed_device=True,
    )
    assert decision.effect is DecisionEffect.STEP_UP


def test_hard_failures() -> None:
    rule = PolicyRule(
        id="allow",
        match=Selector(roles=("sre",)),
        min_trust=0,
        require_managed_device=True,
        require_corporate_network=True,
        forbid_anonymized_network=True,
        min_assurance=AssuranceLevel.HARDWARE,
    )
    pdp = _pdp(rule)
    unmanaged = pdp.authorize(
        principal=ALICE,
        resource=PAYMENTS,
        action="read",
        network=CORP,
        trust=trust(99),
        managed_device=False,
    )
    assert unmanaged.effect is DecisionEffect.DENY
    assert any("managed" in reason for reason in unmanaged.reasons)

    stale = pdp.authorize(
        principal=ALICE,
        resource=PAYMENTS,
        action="read",
        network=CORP,
        trust=trust(99, fail=True),
        managed_device=True,
    )
    assert stale.effect is DecisionEffect.DENY

    anonymized = pdp.authorize(
        principal=ALICE,
        resource=PAYMENTS,
        action="read",
        network=NetworkContext(corporate=True, tor_exit=True),
        trust=trust(99),
        managed_device=True,
    )
    assert anonymized.effect is DecisionEffect.DENY


def test_specificity_prefers_more_specific_allow() -> None:
    broad = PolicyRule(id="broad", match=Selector(roles=("sre",)), min_trust=0)
    specific = PolicyRule(
        id="specific",
        match=Selector(principals=("alice",), resources=("payments-db",)),
        min_trust=95,
    )
    decision = _pdp(broad, specific).authorize(
        principal=ALICE,
        resource=PAYMENTS,
        action="read",
        network=CORP,
        trust=trust(90),
        managed_device=True,
    )
    # The specific rule governs, so trust 90 < 95 denies despite the broad allow.
    assert decision.matched_rule == "specific"
    assert decision.effect is DecisionEffect.DENY


def _decision(effect: DecisionEffect, score: float, *, fail: bool = False) -> Decision:
    return Decision(
        effect=effect,
        principal_id="alice",
        resource_id="payments-db",
        action="read",
        trust=trust(score, fail=fail),
        reasons=("test",),
    )


def test_session_transitions() -> None:
    store = SessionStore()
    session = store.start("s1", principal_id="alice", device_id="laptop", at_epoch=0)
    store.record(
        session,
        decision=_decision(DecisionEffect.PERMIT, 90),
        at_epoch=0,
        resource_id="r",
        action="read",
    )
    assert session.state is SessionState.ACTIVE

    store.record(
        session,
        decision=_decision(DecisionEffect.STEP_UP, 70),
        at_epoch=10,
        resource_id="r",
        action="read",
    )
    assert session.state is SessionState.STEP_UP_REQUIRED

    store.record(
        session,
        decision=_decision(DecisionEffect.DENY, 65),
        at_epoch=20,
        resource_id="r",
        action="read",
    )
    # A plain policy deny with healthy trust does not tear the session down.
    assert session.state is SessionState.STEP_UP_REQUIRED


def test_session_revokes_on_low_trust_and_stays_revoked() -> None:
    store = SessionStore()
    session = store.start("s2", principal_id="alice", device_id="laptop", at_epoch=0)
    store.record(
        session,
        decision=_decision(DecisionEffect.DENY, 10),
        at_epoch=0,
        resource_id="r",
        action="read",
    )
    assert session.state is SessionState.REVOKED
    store.record(
        session,
        decision=_decision(DecisionEffect.PERMIT, 99),
        at_epoch=10,
        resource_id="r",
        action="read",
    )
    assert session.state is SessionState.REVOKED


def test_session_revokes_on_fail_closed() -> None:
    store = SessionStore()
    session = store.start("s3", principal_id="alice", device_id="laptop", at_epoch=0)
    store.record(
        session,
        decision=_decision(DecisionEffect.DENY, 80, fail=True),
        at_epoch=5,
        resource_id="r",
        action="read",
    )
    assert session.state is SessionState.REVOKED
    assert session.age_seconds(65) == 65
    assert session.seconds_since_last(65) == 60
