"""Smoke-test the installed wheel from outside the source checkout.

Run by CI after ``uv pip install`` in a throwaway environment. It exercises the
packaged fixtures, the full evaluation path, and the scenario suite without any
access to the repository, proving the wheel is self-contained.
"""

from __future__ import annotations

from zero_trust_mesh.loader import load_default_mesh, load_default_policies
from zero_trust_mesh.mesh import MeshController
from zero_trust_mesh.models import AccessRequest, DecisionEffect, NetworkContext
from zero_trust_mesh.scenarios import run_all


def main() -> int:
    controller = MeshController(load_default_mesh(), load_default_policies())

    request = AccessRequest(
        session_id="smoke",
        principal_id="alice",
        device_id="laptop-alice",
        resource_id="payments-db",
        action="read",
        network=NetworkContext(corporate=True, country="FR"),
    )
    decision = controller.evaluate(request)
    if decision.effect is not DecisionEffect.PERMIT:
        print(f"unexpected baseline decision: {decision.effect}")
        return 1

    results = run_all(MeshController(load_default_mesh(), load_default_policies()))
    if not all(result.matched for result in results):
        print("scenario suite did not match ground truth")
        return 1

    print(f"ok: baseline permitted, {len(results)} scenarios matched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
