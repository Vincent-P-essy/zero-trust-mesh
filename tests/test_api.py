from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from zero_trust_mesh.api import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_healthz(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_jwks_exposes_keys(client: TestClient) -> None:
    keys = client.get("/oidc/jwks.json").json()["keys"]
    assert keys and keys[0]["kty"] == "RSA"


def test_token_introspect_revoke_flow(client: TestClient) -> None:
    token = client.post(
        "/oidc/token", json={"subject": "alice", "device_id": "laptop-alice"}
    ).json()["access_token"]

    introspected = client.post("/oidc/introspect", json={"token": token}).json()
    assert introspected["active"] is True
    jti = introspected["claims"]["jti"]

    assert client.post("/oidc/revoke", json={"jti": jti}).json()["revoked"] is True
    assert client.post("/oidc/introspect", json={"token": token}).json()["active"] is False


def test_mesh_topology(client: TestClient) -> None:
    mesh = client.get("/mesh").json()
    assert {p["id"] for p in mesh["principals"]} >= {"alice", "bob"}
    assert mesh["policies"]


def test_mesh_request_permits_compliant_access(client: TestClient) -> None:
    response = client.post(
        "/mesh/request",
        json={
            "session_id": "api-demo",
            "principal_id": "alice",
            "device_id": "laptop-alice",
            "resource_id": "payments-db",
            "action": "read",
            "assurance": "aal2",
            "network": {"corporate": True, "country": "FR"},
        },
    )
    body = response.json()
    assert body["decision"]["effect"] == "permit"
    assert body["session"]["state"] == "active"


def test_scenarios_listing_and_run(client: TestClient) -> None:
    listing = client.get("/scenarios").json()
    assert len(listing["scenarios"]) == 9

    run = client.post("/scenarios/posture-drop-revoke/run").json()
    assert run["matched"] is True
    assert run["final_state"] == "revoked"

    assert client.post("/scenarios/does-not-exist/run").status_code == 404


def test_report_endpoint(client: TestClient) -> None:
    report = client.get("/report").json()
    assert report["summary"]["matched"] == report["summary"]["scenarios"]


def test_dashboard_served(client: TestClient) -> None:
    assert client.get("/").status_code == 200
