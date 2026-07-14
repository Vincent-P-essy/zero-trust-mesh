"""Deterministic benchmark over the scenario suite.

The benchmark runs every scenario ``iterations`` times, verifies each step and
final session state against the committed ground truth, and measures latency.
Because the engine is deterministic, every pass produces byte-identical outcomes;
the benchmark asserts this by collecting a single stable hash of the outcome
mapping across all passes. Timing is measured but deliberately excluded from the
hash so a slow CI runner does not change the recorded evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .loader import load_default_mesh, load_default_policies
from .mesh import MeshController
from .scenarios import ScenarioResult, ground_truth, run_all


@dataclass(frozen=True)
class BenchmarkResult:
    iterations: int
    scenarios: int
    steps_per_pass: int
    matched_scenarios: int
    ground_truth_verified: bool
    deterministic: bool
    report_hash: str
    latency_pass_p50_ms: float
    latency_pass_p95_ms: float
    latency_request_mean_ms: float
    elapsed_seconds: float
    source_revision: str
    source_tree_state: str


def _percentile(samples: list[float], pct: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    rank = max(0, min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1))))
    return round(ordered[rank], 4)


def _outcome_map(results: list[ScenarioResult]) -> dict[str, dict[str, object]]:
    return {
        result.scenario.name: {
            "effects": [outcome.decision.effect.value for outcome in result.outcomes],
            "final_state": result.final_state.value,
        }
        for result in results
    }


def _hash(outcomes: dict[str, dict[str, object]]) -> str:
    payload = json.dumps(outcomes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def benchmark(iterations: int = 100) -> BenchmarkResult:
    """Run the scenario suite ``iterations`` times and return measured evidence."""

    mesh = load_default_mesh()
    policies = load_default_policies()
    controller = MeshController(mesh, policies)
    declared = ground_truth()

    durations_ms: list[float] = []
    hashes: set[str] = set()
    matched = 0
    ground_truth_verified = True
    steps_per_pass = 0
    started = time.perf_counter()

    for iteration in range(iterations):
        pass_start = time.perf_counter()
        results = run_all(controller, suffix=str(iteration))
        durations_ms.append((time.perf_counter() - pass_start) * 1000)

        outcomes = _outcome_map(results)
        hashes.add(_hash(outcomes))
        if iteration == 0:
            matched = sum(1 for result in results if result.matched)
            steps_per_pass = sum(len(result.outcomes) for result in results)
            for name, observed in outcomes.items():
                if observed != declared[name]:
                    ground_truth_verified = False

    elapsed = time.perf_counter() - started
    total_requests = steps_per_pass * iterations
    request_mean = round(sum(durations_ms) / total_requests, 4) if total_requests else 0.0

    return BenchmarkResult(
        iterations=iterations,
        scenarios=len(declared),
        steps_per_pass=steps_per_pass,
        matched_scenarios=matched,
        ground_truth_verified=ground_truth_verified,
        deterministic=len(hashes) == 1,
        report_hash=next(iter(hashes)) if hashes else "",
        latency_pass_p50_ms=_percentile(durations_ms, 50),
        latency_pass_p95_ms=_percentile(durations_ms, 95),
        latency_request_mean_ms=request_mean,
        elapsed_seconds=round(elapsed, 4),
        source_revision=os.environ.get("ZTMESH_SOURCE_REVISION", "unknown"),
        source_tree_state=os.environ.get("ZTMESH_SOURCE_TREE_STATE", "unknown"),
    )


def write_benchmark(out_dir: Path, result: BenchmarkResult) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "benchmark.json"
    path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
