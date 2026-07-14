from __future__ import annotations

import pytest

from zero_trust_mesh.loader import load_default_mesh, load_default_policies
from zero_trust_mesh.mesh import MeshController
from zero_trust_mesh.models import Mesh, PolicySet


@pytest.fixture
def mesh() -> Mesh:
    return load_default_mesh()


@pytest.fixture
def policies() -> PolicySet:
    return load_default_policies()


@pytest.fixture
def controller(mesh: Mesh, policies: PolicySet) -> MeshController:
    return MeshController(mesh, policies)
