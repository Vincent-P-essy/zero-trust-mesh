"""Command-line interface for the Zero Trust mesh."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

import uvicorn

from .benchmark import benchmark, write_benchmark
from .loader import load_default_mesh, load_default_policies, load_mesh, load_policies
from .mesh import MeshController, RequestContext
from .models import AccessRequest, AssuranceLevel, NetworkContext
from .reporting import build_report, decision_to_dict, write_report
from .scenarios import SCENARIOS, run_all, run_scenario


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="ztmesh", description="Zero Trust access mesh")
    root.add_argument("--mesh", type=Path, help="path to a mesh YAML file")
    root.add_argument("--policies", type=Path, help="path to a policy YAML file")
    commands = root.add_subparsers(dest="command", required=True)

    authorize = commands.add_parser("authorize", help="evaluate one access request")
    authorize.add_argument("--principal", required=True)
    authorize.add_argument("--device", required=True)
    authorize.add_argument("--resource", required=True)
    authorize.add_argument("--action", default="read")
    authorize.add_argument("--session", default="cli-session")
    authorize.add_argument(
        "--assurance", default="aal2", choices=[level.value for level in AssuranceLevel]
    )
    authorize.add_argument("--country", default="FR")
    authorize.add_argument("--corporate", action="store_true")
    authorize.add_argument("--tor", action="store_true")

    scenario = commands.add_parser("scenario", help="run a named scenario or all of them")
    scenario.add_argument("name", nargs="?", default="all")

    report = commands.add_parser("report", help="run the scenario suite and write a report")
    report.add_argument("--out", type=Path, default=Path("reports"))

    token = commands.add_parser("token", help="issue a certificate-bound demo token")
    token.add_argument("--subject", required=True)
    token.add_argument("--device", required=True)

    run_benchmark = commands.add_parser("benchmark", help="measure the scenario suite")
    run_benchmark.add_argument("--iterations", type=int, default=100)
    run_benchmark.add_argument("--out", type=Path, default=Path("reports"))

    serve = commands.add_parser("serve", help="start the local API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)

    return root


def _controller(args: argparse.Namespace) -> MeshController:
    mesh = load_mesh(args.mesh) if args.mesh else load_default_mesh()
    policies = load_policies(args.policies) if args.policies else load_default_policies()
    return MeshController(mesh, policies)


def _print(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)

    if args.command == "authorize":
        controller = _controller(args)
        request = AccessRequest(
            session_id=args.session,
            principal_id=args.principal,
            device_id=args.device,
            resource_id=args.resource,
            action=args.action,
            network=NetworkContext(
                country=args.country, corporate=args.corporate, tor_exit=args.tor
            ),
        )
        context = RequestContext(assurance=AssuranceLevel(args.assurance))
        decision = controller.evaluate(request, context)
        _print(decision_to_dict(decision))
        return 0

    if args.command == "scenario":
        controller = _controller(args)
        if args.name == "all":
            results = run_all(controller)
            _print(
                {
                    "matched": sum(1 for r in results if r.matched),
                    "total": len(results),
                    "scenarios": [
                        {
                            "name": r.scenario.name,
                            "matched": r.matched,
                            "state": r.final_state.value,
                        }
                        for r in results
                    ],
                }
            )
            return 0
        scenario = next((s for s in SCENARIOS if s.name == args.name), None)
        if scenario is None:
            print(f"unknown scenario: {args.name}")
            return 2
        result = run_scenario(controller, scenario)
        _print(
            {
                "name": scenario.name,
                "matched": result.matched,
                "final_state": result.final_state.value,
                "steps": [
                    {
                        "resource": o.step.resource_id,
                        "expected": o.step.expect.value,
                        "observed": o.decision.effect.value,
                        "trust_score": o.decision.trust.score,
                        "reason": o.decision.reasons[0] if o.decision.reasons else "",
                    }
                    for o in result.outcomes
                ],
            }
        )
        return 0

    if args.command == "report":
        controller = _controller(args)
        results = run_all(controller)
        report = build_report(controller, results)
        paths = write_report(args.out, report, controller.mesh)
        _print({key: str(path) for key, path in paths.items()})
        return 0

    if args.command == "token":
        controller = _controller(args)
        value, certificate = controller.mint_token(subject=args.subject, device_id=args.device)
        _print(
            {
                "access_token": value,
                "audience": controller.audience,
                "cnf_certificate_thumbprint": controller.idp.certificate_thumbprint(certificate),
            }
        )
        return 0

    if args.command == "benchmark":
        measured = benchmark(iterations=args.iterations)
        path = write_benchmark(args.out, measured)
        _print({"benchmark": str(path), **asdict(measured)})
        return 0

    if args.command == "serve":
        uvicorn.run(
            "zero_trust_mesh.api:create_app",
            host=args.host,
            port=args.port,
            factory=True,
            log_level="info",
        )
        return 0

    return 2  # pragma: no cover - argparse requires a subcommand


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
