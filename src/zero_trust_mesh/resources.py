"""Locate packaged data whether running from source or an installed wheel.

The wheel force-includes the fixtures under ``zero_trust_mesh/data`` and the
dashboard under ``zero_trust_mesh/web`` so the default CLI commands work outside
a source checkout. In a source tree those files live at the repository root.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from pathlib import Path


@lru_cache
def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def packaged_path(name: str) -> Path:
    """Return the path to a packaged fixture by file name."""

    try:
        candidate = Path(str(resources.files("zero_trust_mesh") / "data" / name))
        if candidate.exists():
            return candidate
    except (ModuleNotFoundError, FileNotFoundError):  # pragma: no cover - import edge
        pass
    return _repo_root() / "fixtures" / name


def web_dir() -> Path:
    """Return the directory holding the static dashboard."""

    try:
        candidate = Path(str(resources.files("zero_trust_mesh") / "web"))
        if (candidate / "index.html").exists():
            return candidate
    except (ModuleNotFoundError, FileNotFoundError):  # pragma: no cover - import edge
        pass
    return _repo_root() / "web"
