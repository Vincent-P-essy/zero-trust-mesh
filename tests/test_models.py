from __future__ import annotations

import pytest
from pydantic import ValidationError

from zero_trust_mesh.models import (
    AssuranceLevel,
    Device,
    DevicePosture,
    Mesh,
    PolicyRule,
    Principal,
    Resource,
    Selector,
    Sensitivity,
    SignalCategory,
    TrustAssessment,
    TrustFactor,
)


def test_mesh_rejects_duplicate_ids() -> None:
    with pytest.raises(ValidationError):
        Mesh(
            principals=(
                Principal(id="alice"),
                Principal(id="alice"),
            )
        )


def test_mesh_lookup_helpers() -> None:
    mesh = Mesh(
        principals=(Principal(id="alice"),),
        devices=(Device(id="laptop", owner="alice"),),
        resources=(Resource(id="db", service="payments"),),
    )
    assert mesh.principal("alice") is not None
    assert mesh.device("laptop") is not None
    assert mesh.resource("db") is not None
    assert mesh.principal("ghost") is None


def test_step_up_below_must_exceed_min_trust() -> None:
    with pytest.raises(ValidationError):
        PolicyRule(id="r", match=Selector(), min_trust=90, step_up_below_trust=50)


def test_unknown_field_is_forbidden() -> None:
    with pytest.raises(ValidationError):
        DevicePosture(unexpected=True)  # type: ignore[call-arg]


def test_trust_assessment_partitions_factors() -> None:
    assessment = TrustAssessment(
        score=42.0,
        assurance=AssuranceLevel.MULTI_FACTOR,
        factors=(
            TrustFactor(category=SignalCategory.DEVICE, name="good", contribution=10, detail="x"),
            TrustFactor(category=SignalCategory.NETWORK, name="bad", contribution=-5, detail="y"),
        ),
    )
    assert len(assessment.positive) == 1
    assert len(assessment.penalties) == 1


def test_identifier_pattern_is_enforced() -> None:
    with pytest.raises(ValidationError):
        Resource(id="Bad Id With Spaces", service="payments", sensitivity=Sensitivity.PUBLIC)
