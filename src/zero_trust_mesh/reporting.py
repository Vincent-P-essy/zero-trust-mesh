"""Serialize decisions, sessions, and scenario runs into review artifacts.

Reports are plain data: a JSON document for tooling, a Markdown summary for
humans, and a Graphviz DOT rendering of the mesh topology. Nothing here makes a
decision; it only presents what the engine produced.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .mesh import MeshController
from .models import Decision, Mesh, SessionSummary
from .scenarios import ScenarioResult


def decision_to_dict(decision: Decision) -> dict[str, Any]:
    return {
        "effect": decision.effect.value,
        "principal": decision.principal_id,
        "resource": decision.resource_id,
        "action": decision.action,
        "matched_rule": decision.matched_rule,
        "trust_score": decision.trust.score,
        "assurance": decision.trust.assurance.value,
        "fail_closed": decision.trust.fail_closed,
        "reasons": list(decision.reasons),
        "obligations": [{"kind": o.kind, "detail": o.detail} for o in decision.obligations],
        "trust_factors": [
            {
                "category": f.category.value,
                "name": f.name,
                "contribution": f.contribution,
                "detail": f.detail,
            }
            for f in decision.trust.factors
        ],
    }


def session_to_dict(summary: SessionSummary) -> dict[str, Any]:
    return {
        "session_id": summary.session_id,
        "principal": summary.principal_id,
        "device": summary.device_id,
        "state": summary.state.value,
        "permitted": summary.permitted_count,
        "denied": summary.denied_count,
        "timeline": [
            {
                "sequence": e.sequence,
                "at_epoch": e.at_epoch,
                "resource": e.resource_id,
                "action": e.action,
                "effect": e.effect.value,
                "trust_score": e.trust_score,
                "state": e.state.value,
                "reason": e.reason,
            }
            for e in summary.events
        ],
    }


def scenario_result_to_dict(result: ScenarioResult) -> dict[str, Any]:
    return {
        "name": result.scenario.name,
        "description": result.scenario.description,
        "principal": result.scenario.principal_id,
        "device": result.scenario.device_id,
        "matched": result.matched,
        "final_state": result.final_state.value,
        "expected_final_state": result.scenario.expect_final_state.value,
        "steps": [
            {
                "resource": o.step.resource_id,
                "action": o.step.action,
                "at_epoch": o.step.at_epoch,
                "expected": o.step.expect.value,
                "observed": o.decision.effect.value,
                "trust_score": o.decision.trust.score,
                "matched": o.matched,
                "reason": o.decision.reasons[0] if o.decision.reasons else "",
            }
            for o in result.outcomes
        ],
    }


def build_report(controller: MeshController, results: list[ScenarioResult]) -> dict[str, Any]:
    mesh = controller.mesh
    return {
        "mesh": mesh.name,
        "trust_domain": mesh.trust_domain,
        "counts": {
            "principals": len(mesh.principals),
            "devices": len(mesh.devices),
            "resources": len(mesh.resources),
            "services": len(mesh.services),
            "policies": len(controller.policy_set.rules),
        },
        "scenarios": [scenario_result_to_dict(r) for r in results],
        "sessions": [session_to_dict(session.summary()) for session in _sessions(controller)],
        "summary": {
            "scenarios": len(results),
            "matched": sum(1 for r in results if r.matched),
        },
    }


def _sessions(controller: MeshController) -> list[Any]:
    store = controller.sessions
    return [store.get(sid) for sid in _session_ids(controller) if store.get(sid) is not None]


def _session_ids(controller: MeshController) -> list[str]:
    # Sessions are keyed internally; expose ids via their summaries.
    return [s.session_id for s in controller.sessions._sessions.values()]


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# Zero Trust mesh report: {report['mesh']}",
        "",
        f"Trust domain `{report['trust_domain']}`.",
        "",
        "| Scenario | Expected | Observed final state | Matched |",
        "|---|---|---|---|",
    ]
    for scenario in report["scenarios"]:
        effects = " -> ".join(step["observed"] for step in scenario["steps"])
        lines.append(
            f"| {scenario['name']} | {scenario['final_state']} | {effects} | "
            f"{'yes' if scenario['matched'] else 'NO'} |"
        )
    matched = report["summary"]["matched"]
    total = report["summary"]["scenarios"]
    lines += ["", f"**{matched}/{total} scenarios match their declared ground truth.**", ""]
    return "\n".join(lines)


def render_dot(mesh: Mesh) -> str:
    lines = ["digraph mesh {", "  rankdir=LR;", '  node [shape=box, fontname="Helvetica"];']
    for service in mesh.services:
        lines.append(
            f'  "svc:{service.id}" [label="{service.id}", style=filled, fillcolor="#e8eef7"];'
        )
    for resource in mesh.resources:
        lines.append(
            f'  "res:{resource.id}" [label="{resource.id}\\n{resource.sensitivity.value}"];'
        )
        lines.append(f'  "svc:{resource.service}" -> "res:{resource.id}";')
    lines.append("}")
    return "\n".join(lines)


def write_report(out_dir: Path, report: dict[str, Any], mesh: Mesh) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"
    dot_path = out_dir / "mesh.dot"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    dot_path.write_text(render_dot(mesh) + "\n", encoding="utf-8")
    return {"json": json_path, "markdown": md_path, "dot": dot_path}
