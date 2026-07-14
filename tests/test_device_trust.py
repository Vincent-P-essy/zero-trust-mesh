from __future__ import annotations

from zero_trust_mesh.device import ATTESTATION_TTL_SECONDS, score_device
from zero_trust_mesh.models import AssuranceLevel, DevicePosture, NetworkContext
from zero_trust_mesh.trust import TrustEngine, TrustInputs, score_network

COMPLIANT = DevicePosture(
    managed=True,
    disk_encrypted=True,
    screen_lock=True,
    firewall=True,
    edr_active=True,
    secure_boot=True,
    os_patch_age_days=2,
)


def test_compliant_device_scores_one_hundred() -> None:
    score, factors, failed = score_device(COMPLIANT)
    assert score == 100.0
    assert failed is False
    assert all(f.contribution >= 0 for f in factors)


def test_missing_controls_lower_the_score() -> None:
    posture = COMPLIANT.model_copy(update={"disk_encrypted": False, "edr_active": False})
    score, _factors, _failed = score_device(posture)
    assert score == 100.0 - 20.0 - 18.0


def test_patch_age_thresholds() -> None:
    fresh = score_device(COMPLIANT.model_copy(update={"os_patch_age_days": 10}))[0]
    month = score_device(COMPLIANT.model_copy(update={"os_patch_age_days": 25}))[0]
    quarter = score_device(COMPLIANT.model_copy(update={"os_patch_age_days": 60}))[0]
    ancient = score_device(COMPLIANT.model_copy(update={"os_patch_age_days": 400}))[0]
    assert fresh == 100.0
    assert month == 94.0
    assert quarter == 86.0
    assert ancient == 76.0


def test_jailbreak_is_a_heavy_penalty() -> None:
    score, factors, _failed = score_device(COMPLIANT.model_copy(update={"jailbroken": True}))
    assert score == 40.0
    assert any(f.name == "jailbroken" for f in factors)


def test_stale_attestation_fails_closed() -> None:
    posture = COMPLIANT.model_copy(update={"attestation_age_seconds": ATTESTATION_TTL_SECONDS + 1})
    score, factors, failed = score_device(posture)
    assert failed is True
    assert score == 5.0
    assert factors[0].name == "stale_attestation"


def test_network_scoring() -> None:
    corporate, _ = score_network(NetworkContext(corporate=True))
    tor, _ = score_network(NetworkContext(tor_exit=True))
    vpn, _ = score_network(NetworkContext(anonymizing_vpn=True))
    assert corporate == 85.0
    assert tor == 0.0
    assert vpn == 30.0


def test_trust_blend_and_decay() -> None:
    engine = TrustEngine()
    base = engine.assess(
        TrustInputs(
            assurance=AssuranceLevel.MULTI_FACTOR,
            posture=COMPLIANT,
            network=NetworkContext(corporate=True),
            amr=("pwd", "webauthn"),
        )
    )
    assert base.score == 91.0
    assert base.assurance is AssuranceLevel.MULTI_FACTOR

    decayed = engine.assess(
        TrustInputs(
            assurance=AssuranceLevel.MULTI_FACTOR,
            posture=COMPLIANT,
            network=NetworkContext(corporate=True),
            amr=("pwd", "webauthn"),
            session_age_seconds=3600,
        )
    )
    assert decayed.score < base.score
    assert any(f.name == "session_decay" for f in decayed.factors)


def test_trust_impossible_travel_and_new_device() -> None:
    engine = TrustEngine()
    assessment = engine.assess(
        TrustInputs(
            assurance=AssuranceLevel.MULTI_FACTOR,
            posture=COMPLIANT,
            network=NetworkContext(country="RU"),
            prior_country="FR",
            seconds_since_last_request=120,
            new_device=True,
        )
    )
    names = {f.name for f in assessment.factors}
    assert "impossible_travel" in names
    assert "new_device" in names


def test_trust_propagates_fail_closed() -> None:
    engine = TrustEngine()
    stale = COMPLIANT.model_copy(update={"attestation_age_seconds": 999_999})
    assessment = engine.assess(
        TrustInputs(
            assurance=AssuranceLevel.MULTI_FACTOR,
            posture=stale,
            network=NetworkContext(corporate=True),
        )
    )
    assert assessment.fail_closed is True
