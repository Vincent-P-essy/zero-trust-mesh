from __future__ import annotations

import json
from pathlib import Path

import pytest

from zero_trust_mesh.cli import main


def _capture(capsys: pytest.CaptureFixture[str]) -> dict:
    return json.loads(capsys.readouterr().out)


def test_authorize_permits(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "authorize",
            "--principal",
            "alice",
            "--device",
            "laptop-alice",
            "--resource",
            "payments-db",
            "--corporate",
            "--assurance",
            "aal2",
        ]
    )
    assert code == 0
    assert _capture(capsys)["effect"] == "permit"


def test_authorize_denies_from_tor(capsys: pytest.CaptureFixture[str]) -> None:
    main(
        [
            "authorize",
            "--principal",
            "alice",
            "--device",
            "laptop-alice",
            "--resource",
            "payments-db",
            "--tor",
        ]
    )
    assert _capture(capsys)["effect"] == "deny"


def test_scenario_all(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scenario", "all"]) == 0
    payload = _capture(capsys)
    assert payload["matched"] == payload["total"] == 9


def test_scenario_named(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scenario", "step-up-required"]) == 0
    assert _capture(capsys)["final_state"] == "step_up_required"


def test_scenario_unknown(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scenario", "nope"]) == 2


def test_token(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["token", "--subject", "alice", "--device", "laptop-alice"]) == 0
    assert "access_token" in _capture(capsys)


def test_report_writes_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["report", "--out", str(tmp_path)]) == 0
    paths = _capture(capsys)
    assert Path(paths["json"]).exists()


def test_benchmark_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["benchmark", "--iterations", "2", "--out", str(tmp_path)]) == 0
    assert _capture(capsys)["deterministic"] is True
