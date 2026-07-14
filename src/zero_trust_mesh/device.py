"""Deterministic device-trust scoring.

The scorer converts an attested :class:`DevicePosture` into a 0-100 component
score and a list of :class:`TrustFactor` evidence entries. Weights are fixed and
documented in ``docs/TRUST_MODEL.md``; there is no learned model. A stale
attestation is treated as unknown posture and fails closed to a low score so a
device that stopped reporting cannot retain trust indefinitely.
"""

from __future__ import annotations

from .models import DevicePosture, SignalCategory, TrustFactor

# Maximum attestation age before posture is considered unknown (12 hours).
ATTESTATION_TTL_SECONDS = 43_200

# Positive controls and the trust points each contributes when present. The
# weights are chosen so a fully compliant device reaches exactly 100 before any
# patch-age or integrity penalty is applied.
_POSITIVE_CONTROLS: tuple[tuple[str, str, float], ...] = (
    ("managed", "device is enrolled in management", 24.0),
    ("disk_encrypted", "full-disk encryption enabled", 20.0),
    ("edr_active", "endpoint detection agent reporting", 18.0),
    ("secure_boot", "verified/secure boot enabled", 14.0),
    ("screen_lock", "screen lock enforced", 12.0),
    ("firewall", "host firewall enabled", 12.0),
)

# Patch-age thresholds in days mapped to a penalty applied to the score.
_PATCH_PENALTIES: tuple[tuple[int, float], ...] = (
    (14, 0.0),
    (30, -6.0),
    (90, -14.0),
    (10_000, -24.0),
)


def _patch_penalty(days: int) -> float:
    for threshold, penalty in _PATCH_PENALTIES:
        if days <= threshold:
            return penalty
    return _PATCH_PENALTIES[-1][1]


def score_device(posture: DevicePosture) -> tuple[float, tuple[TrustFactor, ...], bool]:
    """Return ``(score, factors, fail_closed)`` for a device posture.

    ``score`` is clamped to ``[0, 100]``. ``fail_closed`` is ``True`` when the
    attestation is too old to trust, in which case the score is capped low.
    """

    factors: list[TrustFactor] = []
    fail_closed = posture.attestation_age_seconds > ATTESTATION_TTL_SECONDS

    if fail_closed:
        factors.append(
            TrustFactor(
                category=SignalCategory.DEVICE,
                name="stale_attestation",
                contribution=0.0,
                detail=(
                    f"attestation is {posture.attestation_age_seconds}s old "
                    f"(> {ATTESTATION_TTL_SECONDS}s); posture treated as unknown"
                ),
            )
        )
        # An unknown device keeps only a small baseline of trust.
        return 5.0, tuple(factors), True

    score = 0.0
    for field, detail, weight in _POSITIVE_CONTROLS:
        present = bool(getattr(posture, field))
        contribution = weight if present else 0.0
        score += contribution
        factors.append(
            TrustFactor(
                category=SignalCategory.DEVICE,
                name=field,
                contribution=contribution,
                detail=detail if present else f"missing: {detail}",
            )
        )

    patch_penalty = _patch_penalty(posture.os_patch_age_days)
    score += patch_penalty
    factors.append(
        TrustFactor(
            category=SignalCategory.DEVICE,
            name="os_patch_age",
            contribution=patch_penalty,
            detail=f"os patched {posture.os_patch_age_days} day(s) ago",
        )
    )

    if posture.jailbroken:
        score -= 60.0
        factors.append(
            TrustFactor(
                category=SignalCategory.DEVICE,
                name="jailbroken",
                contribution=-60.0,
                detail="device reports jailbreak/root; integrity compromised",
            )
        )

    score = max(0.0, min(100.0, score))
    return round(score, 3), tuple(factors), False
