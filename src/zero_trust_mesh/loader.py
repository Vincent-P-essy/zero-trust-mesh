"""Load the mesh and policy set from YAML, with strict validation.

YAML is parsed with the safe loader; the resulting mapping is handed to the
frozen pydantic models, which reject unknown fields and out-of-range values.
Invalid fixtures raise rather than loading a partially valid environment.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import Mesh, PolicySet
from .resources import packaged_path

MAX_DOCUMENT_BYTES = 1_048_576


def _read_yaml(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"{path} exceeds {MAX_DOCUMENT_BYTES} bytes")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a top-level mapping")
    return data


def load_mesh(path: Path) -> Mesh:
    return Mesh.model_validate(_read_yaml(path))


def load_policies(path: Path) -> PolicySet:
    return PolicySet.model_validate(_read_yaml(path))


def load_default_mesh() -> Mesh:
    return load_mesh(packaged_path("mesh.yaml"))


def load_default_policies() -> PolicySet:
    return load_policies(packaged_path("policies.yaml"))
