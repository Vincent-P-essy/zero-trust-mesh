"""Continuous trust scoring.

The engine blends four signal categories into a single 0-100 trust score:

* **identity** - authentication assurance (AAL) and the methods used;
* **device** - the posture score from :mod:`zero_trust_mesh.device`;
* **network** - reputation of the origin network;
* **behavior/session** - how the score decays as a session ages and how
  anomalies (impossible travel, a never-seen device) reduce it.

The blend is a fixed weighted mean of the first three categories, after which
behavioral penalties are subtracted. Every input leaves a :class:`TrustFactor`
so a decision can be explained. Weights live in ``docs/TRUST_MODEL.md``. Nothing
here is learned or probabilistic; identical inputs always yield an identical
score, which is what makes the benchmark reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .device import score_device
from .models import (
    AssuranceLevel,
    DevicePosture,
    NetworkContext,
    SignalCategory,
    TrustAssessment,
    TrustFactor,
)

# Weights of the three primary components; they sum to 1.0.
WEIGHT_IDENTITY = 0.35
WEIGHT_DEVICE = 0.40
WEIGHT_NETWORK = 0.25

# Trust points lost per full 5-minute block a session runs without re-auth,
# after a 15-minute grace period, capped so a stale session floors out.
SESSION_DECAY_PER_BLOCK = 4.0
SESSION_DECAY_GRACE_SECONDS = 900
SESSION_DECAY_BLOCK_SECONDS = 300
SESSION_DECAY_CAP = 40.0

_ASSURANCE_BASE: dict[AssuranceLevel, float] = {
    AssuranceLevel.NONE: 10.0,
    AssuranceLevel.SINGLE_FACTOR: 45.0,
    AssuranceLevel.MULTI_FACTOR: 80.0,
    AssuranceLevel.HARDWARE: 95.0,
}


@dataclass(frozen=True)
class TrustInputs:
    """Everything the engine needs to score one request."""

    assurance: AssuranceLevel
    posture: DevicePosture
    network: NetworkContext
    amr: tuple[str, ...] = ()
    session_age_seconds: float = 0.0
    seconds_since_last_request: float = 0.0
    prior_country: str | None = None
    new_device: bool = False
    factors: list[TrustFactor] = field(default_factory=list)


def score_network(network: NetworkContext) -> tuple[float, list[TrustFactor]]:
    """Return a 0-100 network component score and its evidence factors."""

    factors: list[TrustFactor] = []
    score = 55.0
    factors.append(
        TrustFactor(
            category=SignalCategory.NETWORK,
            name="baseline",
            contribution=55.0,
            detail="unclassified network baseline",
        )
    )
    if network.corporate:
        score += 30.0
        factors.append(
            TrustFactor(
                category=SignalCategory.NETWORK,
                name="corporate",
                contribution=30.0,
                detail="request originates from a corporate network range",
            )
        )
    if network.tor_exit:
        score -= 55.0
        factors.append(
            TrustFactor(
                category=SignalCategory.NETWORK,
                name="tor_exit",
                contribution=-55.0,
                detail="origin is a known Tor exit node",
            )
        )
    if network.anonymizing_vpn:
        score -= 25.0
        factors.append(
            TrustFactor(
                category=SignalCategory.NETWORK,
                name="anonymizing_vpn",
                contribution=-25.0,
                detail="origin is a commercial anonymizing VPN",
            )
        )
    return max(0.0, min(100.0, score)), factors


def _identity_component(
    assurance: AssuranceLevel, amr: tuple[str, ...]
) -> tuple[float, list[TrustFactor]]:
    base = _ASSURANCE_BASE[assurance]
    factors = [
        TrustFactor(
            category=SignalCategory.IDENTITY,
            name="assurance",
            contribution=base,
            detail=f"authentication assurance level {assurance.value}",
        )
    ]
    score = base
    if "hwk" in amr or "webauthn" in amr:
        score = min(100.0, score + 5.0)
        factors.append(
            TrustFactor(
                category=SignalCategory.IDENTITY,
                name="phishing_resistant",
                contribution=5.0,
                detail="phishing-resistant authenticator used",
            )
        )
    return score, factors


def _session_decay(age_seconds: float) -> float:
    if age_seconds <= SESSION_DECAY_GRACE_SECONDS:
        return 0.0
    blocks = (age_seconds - SESSION_DECAY_GRACE_SECONDS) / SESSION_DECAY_BLOCK_SECONDS
    return min(SESSION_DECAY_CAP, blocks * SESSION_DECAY_PER_BLOCK)


class TrustEngine:
    """Computes a :class:`TrustAssessment` from :class:`TrustInputs`."""

    def assess(self, inputs: TrustInputs) -> TrustAssessment:
        factors: list[TrustFactor] = list(inputs.factors)

        identity_score, identity_factors = _identity_component(inputs.assurance, inputs.amr)
        device_score, device_factors, device_failed = score_device(inputs.posture)
        network_score, network_factors = score_network(inputs.network)
        factors.extend(identity_factors)
        factors.extend(device_factors)
        factors.extend(network_factors)

        blended = (
            WEIGHT_IDENTITY * identity_score
            + WEIGHT_DEVICE * device_score
            + WEIGHT_NETWORK * network_score
        )

        decay = _session_decay(inputs.session_age_seconds)
        if decay > 0:
            blended -= decay
            factors.append(
                TrustFactor(
                    category=SignalCategory.SESSION,
                    name="session_decay",
                    contribution=-round(decay, 3),
                    detail=(
                        f"session running {int(inputs.session_age_seconds)}s without "
                        "re-authentication"
                    ),
                )
            )

        if (
            inputs.prior_country is not None
            and inputs.network.country != inputs.prior_country
            and inputs.seconds_since_last_request <= 3_600
        ):
            blended -= 45.0
            factors.append(
                TrustFactor(
                    category=SignalCategory.BEHAVIOR,
                    name="impossible_travel",
                    contribution=-45.0,
                    detail=(
                        f"origin moved {inputs.prior_country}->{inputs.network.country} in "
                        f"{int(inputs.seconds_since_last_request)}s"
                    ),
                )
            )

        if inputs.new_device:
            blended -= 15.0
            factors.append(
                TrustFactor(
                    category=SignalCategory.BEHAVIOR,
                    name="new_device",
                    contribution=-15.0,
                    detail="device not previously seen in this session context",
                )
            )

        score = round(max(0.0, min(100.0, blended)), 3)
        return TrustAssessment(
            score=score,
            assurance=inputs.assurance,
            factors=tuple(factors),
            fail_closed=device_failed,
        )
