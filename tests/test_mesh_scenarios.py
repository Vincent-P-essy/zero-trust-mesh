from __future__ import annotations

import json

from zero_trust_mesh.mesh import MeshController, RequestContext
from zero_trust_mesh.models import AccessRequest, DecisionEffect, NetworkContext, SessionState
from zero_trust_mesh.resources import packaged_path
from zero_trust_mesh.scenarios import SCENARIOS, ground_truth, run_all, run_scenario


def test_all_scenarios_match_ground_truth(controller: MeshController) -> None:
    results = run_all(controller)
    assert len(results) == len(SCENARIOS)
    assert all(result.matched for result in results)


def test_ground_truth_matches_committed_fixture() -> None:
    committed = json.loads(packaged_path("ground-truth.json").read_text(encoding="utf-8"))
    assert committed == ground_truth()


def test_unknown_subject_fails_closed(controller: MeshController) -> None:
    request = AccessRequest(
        session_id="s",
        principal_id="ghost",
        device_id="laptop-alice",
        resource_id="payments-db",
        action="read",
    )
    decision = controller.evaluate(request)
    assert decision.effect is DecisionEffect.DENY
    assert decision.trust.fail_closed is True


def test_token_subject_mismatch_is_denied(controller: MeshController) -> None:
    token, certificate = controller.mint_token(subject="bob", device_id="laptop-bob")
    request = AccessRequest(
        session_id="mismatch",
        principal_id="alice",
        device_id="laptop-alice",
        resource_id="payments-db",
        action="read",
        network=NetworkContext(corporate=True),
    )
    decision = controller.evaluate(
        request, RequestContext(token=token, certificate_der=certificate)
    )
    assert decision.effect is DecisionEffect.DENY


def test_invalid_token_is_denied(controller: MeshController) -> None:
    request = AccessRequest(
        session_id="badtok",
        principal_id="alice",
        device_id="laptop-alice",
        resource_id="payments-db",
        action="read",
        network=NetworkContext(corporate=True),
    )
    decision = controller.evaluate(request, RequestContext(token="garbage"))  # noqa: S106
    assert decision.effect is DecisionEffect.DENY
    assert decision.trust.fail_closed is True


def test_revoked_session_short_circuits(controller: MeshController) -> None:
    scenario = next(s for s in SCENARIOS if s.name == "posture-drop-revoke")
    result = run_scenario(controller, scenario)
    assert result.final_state is SessionState.REVOKED
    # The third step is denied purely because the session was already revoked.
    assert result.outcomes[-1].decision.reasons[0].startswith("session was previously revoked")


def test_workload_identity_is_cached(controller: MeshController) -> None:
    first = controller.workload_identity("payments")
    second = controller.workload_identity("payments")
    assert first is second
    assert controller.audience == controller.mesh.trust_domain
