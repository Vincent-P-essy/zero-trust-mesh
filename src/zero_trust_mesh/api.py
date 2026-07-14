"""Local HTTP surface for the mesh: identity provider, PDP, and demo endpoints.

The API is intentionally unauthenticated and is meant to run on loopback for the
dashboard and for exploration. It exposes the identity provider (JWKS, token
issuance, introspection, revocation), a direct authorization endpoint, a mesh
request router that runs the full continuous-verification path, and the scenario
suite. Static dashboard files are served from the package.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .loader import load_default_mesh, load_default_policies
from .mesh import MeshController, RequestContext
from .models import AccessRequest, AssuranceLevel, DevicePosture, NetworkContext
from .reporting import build_report, decision_to_dict, session_to_dict
from .resources import web_dir
from .scenarios import SCENARIOS, run_all, run_scenario


class TokenRequest(BaseModel):
    subject: str
    device_id: str
    workload_service: str = "workstation-agent"
    assurance: AssuranceLevel = AssuranceLevel.MULTI_FACTOR
    amr: tuple[str, ...] = ("pwd", "otp")


class IntrospectRequest(BaseModel):
    token: str


class RevokeRequest(BaseModel):
    jti: str


class MeshRequest(BaseModel):
    session_id: str = Field(default="demo-session")
    principal_id: str
    device_id: str
    resource_id: str
    action: str = "read"
    network: NetworkContext = NetworkContext()
    assurance: AssuranceLevel = AssuranceLevel.MULTI_FACTOR
    amr: tuple[str, ...] = ("pwd", "otp")
    posture: DevicePosture | None = None
    new_device: bool = False
    at_epoch: float = 0.0


def create_app(controller: MeshController | None = None) -> FastAPI:
    app = FastAPI(
        title="Zero Trust mesh",
        version="0.2.0",
        description="Continuous-verification access mesh over a synthetic environment.",
    )
    controller = controller or MeshController(load_default_mesh(), load_default_policies())
    app.state.controller = controller

    def ctrl() -> MeshController:
        return app.state.controller  # type: ignore[no-any-return]

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "mesh": ctrl().mesh.name}

    @app.get("/oidc/jwks.json")
    def jwks() -> dict[str, Any]:
        return ctrl().idp.jwks()

    @app.post("/oidc/token")
    def token(request: TokenRequest) -> dict[str, Any]:
        value, certificate = ctrl().mint_token(
            subject=request.subject,
            device_id=request.device_id,
            workload_service=request.workload_service,
            assurance=request.assurance,
            amr=request.amr,
        )
        return {
            "access_token": value,
            "token_type": "Bearer",
            "audience": ctrl().audience,
            "cnf_certificate_thumbprint": ctrl().idp.certificate_thumbprint(certificate),
        }

    @app.post("/oidc/introspect")
    def introspect(request: IntrospectRequest) -> dict[str, Any]:
        result = ctrl().idp.introspect(request.token, audience=ctrl().audience)
        return {"active": result.active, "claims": result.claims, "reason": result.reason}

    @app.post("/oidc/revoke")
    def revoke(request: RevokeRequest) -> dict[str, bool]:
        ctrl().idp.revoke(request.jti)
        return {"revoked": True}

    @app.get("/mesh")
    def mesh_topology() -> dict[str, Any]:
        mesh = ctrl().mesh
        return {
            "name": mesh.name,
            "trust_domain": mesh.trust_domain,
            "principals": [p.model_dump() for p in mesh.principals],
            "devices": [d.model_dump() for d in mesh.devices],
            "resources": [r.model_dump() for r in mesh.resources],
            "services": [s.model_dump() for s in mesh.services],
            "policies": [rule.model_dump() for rule in ctrl().policy_set.rules],
        }

    @app.post("/mesh/request")
    def mesh_request(request: MeshRequest) -> dict[str, Any]:
        access = AccessRequest(
            session_id=request.session_id,
            principal_id=request.principal_id,
            device_id=request.device_id,
            resource_id=request.resource_id,
            action=request.action,
            network=request.network,
            at_epoch=request.at_epoch,
        )
        context = RequestContext(
            assurance=request.assurance,
            amr=request.amr,
            posture=request.posture,
            new_device=request.new_device,
        )
        decision = ctrl().evaluate(access, context)
        session = ctrl().sessions.get(request.session_id)
        return {
            "decision": decision_to_dict(decision),
            "session": session_to_dict(session.summary()) if session is not None else None,
        }

    @app.get("/scenarios")
    def scenarios() -> dict[str, Any]:
        return {
            "scenarios": [
                {"name": s.name, "description": s.description, "steps": len(s.steps)}
                for s in SCENARIOS
            ]
        }

    @app.post("/scenarios/{name}/run")
    def run_named(name: str) -> dict[str, Any]:
        scenario = next((s for s in SCENARIOS if s.name == name), None)
        if scenario is None:
            raise HTTPException(status_code=404, detail="unknown scenario")
        # Use a fresh controller so scenario runs stay independent of live state.
        fresh = MeshController(load_default_mesh(), load_default_policies())
        result = run_scenario(fresh, scenario)
        session = fresh.sessions.get(scenario.name)
        return {
            "name": name,
            "matched": result.matched,
            "final_state": result.final_state.value,
            "timeline": session_to_dict(session.summary()) if session is not None else None,
            "steps": [
                {
                    "resource": o.step.resource_id,
                    "expected": o.step.expect.value,
                    "observed": o.decision.effect.value,
                    "trust_score": o.decision.trust.score,
                    "reasons": list(o.decision.reasons),
                }
                for o in result.outcomes
            ],
        }

    @app.get("/report")
    def report() -> JSONResponse:
        fresh = MeshController(load_default_mesh(), load_default_policies())
        results = run_all(fresh)
        return JSONResponse(build_report(fresh, results))

    directory = web_dir()
    if directory.exists():
        app.mount("/", StaticFiles(directory=str(directory), html=True), name="web")

    return app
