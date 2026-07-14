from __future__ import annotations

import json
from pathlib import Path

import pytest

from zero_trust_mesh.benchmark import _percentile, benchmark, write_benchmark
from zero_trust_mesh.loader import (
    load_default_mesh,
    load_default_policies,
    load_mesh,
    load_policies,
)
from zero_trust_mesh.mesh import MeshController
from zero_trust_mesh.models import Mesh, PolicySet
from zero_trust_mesh.reporting import build_report, render_dot, render_markdown, write_report
from zero_trust_mesh.scenarios import run_all


def test_percentile_helper() -> None:
    assert _percentile([], 50) == 0.0
    assert _percentile([1.0, 2.0, 3.0, 4.0], 50) == 3.0
    assert _percentile([1.0, 2.0, 3.0, 4.0], 100) == 4.0
    assert _percentile([5.0], 95) == 5.0


def test_benchmark_is_deterministic() -> None:
    result = benchmark(iterations=5)
    assert result.deterministic is True
    assert result.ground_truth_verified is True
    assert result.matched_scenarios == result.scenarios
    assert result.report_hash


def test_write_benchmark(tmp_path: Path) -> None:
    result = benchmark(iterations=3)
    path = write_benchmark(tmp_path, result)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["iterations"] == 3


def test_build_and_render_report(controller: MeshController, tmp_path: Path) -> None:
    results = run_all(controller)
    report = build_report(controller, results)
    assert report["summary"]["matched"] == report["summary"]["scenarios"]

    markdown = render_markdown(report)
    assert "scenarios match" in markdown

    dot = render_dot(controller.mesh)
    assert dot.startswith("digraph mesh")

    paths = write_report(tmp_path, report, controller.mesh)
    assert paths["json"].exists()
    assert paths["markdown"].exists()
    assert paths["dot"].exists()


def test_loader_roundtrip(tmp_path: Path) -> None:
    mesh = load_default_mesh()
    policies = load_default_policies()
    assert isinstance(mesh, Mesh)
    assert isinstance(policies, PolicySet)

    mesh_path = tmp_path / "mesh.yaml"
    mesh_path.write_text("name: tiny\ntrust_domain: t.internal\n", encoding="utf-8")
    assert load_mesh(mesh_path).name == "tiny"

    policy_path = tmp_path / "p.yaml"
    policy_path.write_text("name: p\ndefault_effect: allow\n", encoding="utf-8")
    assert load_policies(policy_path).default_effect.value == "allow"


def test_loader_rejects_non_mapping(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        load_mesh(bad)


def test_loader_rejects_oversize(tmp_path: Path) -> None:
    big = tmp_path / "big.yaml"
    big.write_text("name: " + "x" * 2_000_000 + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="exceeds"):
        load_mesh(big)
