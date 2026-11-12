"""The CLI drives every SDK operation against the in-process stack."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ciphercompute_client import cli
from ciphercompute_client.errors import ApiError

from .conftest import PASSWORD, Stack

runner = CliRunner()


@pytest.fixture
def cli_env(stack: Stack, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Stack:
    monkeypatch.setattr(cli, "HOME", tmp_path / "home")
    monkeypatch.setenv("CC_KEY_PASSPHRASE", "cli test passphrase")
    monkeypatch.setenv("CC_PASSWORD", PASSWORD)
    monkeypatch.delenv("CC_API_KEY", raising=False)
    monkeypatch.delenv("CC_SERVER", raising=False)
    real = cli.CipherComputeClient

    def factory(server: str, **kwargs: Any) -> Any:
        kwargs.pop("transport_config", None)
        return real(server, http=stack.http, **kwargs)

    monkeypatch.setattr(cli, "CipherComputeClient", factory)
    import ciphercompute_client.keystore as ks

    monkeypatch.setattr(ks, "KDF_TIME_COST", 1)
    monkeypatch.setattr(ks, "KDF_MEMORY_KIB", 8)
    monkeypatch.setattr(ks, "KDF_PARALLELISM", 1)
    return stack


def run(*args: str) -> Any:
    result = runner.invoke(cli.app, ["--json", *args], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    return json.loads(result.output) if result.output.strip() else None


def test_cli_end_to_end(cli_env: Stack, tmp_path: Path) -> None:
    keys = tmp_path / "keys"
    generated = run("keys", "generate", str(keys))
    assert generated["encrypted"] is True and "N=8192" in generated["params"]
    assert run("keys", "info", str(keys))["ring_id"] == generated["ring_id"]

    email = f"cli-{uuid.uuid4().hex[:6]}@example.com"
    registered = run("--server", "https://api.test", "register", "--email", email, "--organization", "CLI Clinic")
    assert registered["role"] == "owner"
    session = json.loads((cli.HOME / cli.SESSION_FILE).read_text(encoding="utf-8"))
    assert session["server"] == "https://api.test" and session["access_token"]
    if os.name == "posix":
        assert oct((cli.HOME / cli.SESSION_FILE).stat().st_mode & 0o777) == "0o600"
    assert run("whoami")["email"] == email

    project = run("projects", "create", "cardio")
    assert [p["name"] for p in run("projects", "list")] == ["cardio"]
    bundle = run("bundles", "upload", project["id"], str(keys))
    assert run("bundles", "list", project["id"])[0]["id"] == bundle["id"]
    dataset = run("datasets", "create", project["id"], "vitals", bundle["id"])
    assert run("datasets", "list", project["id"])[0]["id"] == dataset["id"]

    single = run("datasets", "encrypt-upload", dataset["id"], str(keys), "--values", "120, 130, 140", "--label", "sbp")
    csv_file = tmp_path / "vitals.csv"
    csv_file.write_text("age_z,bp_z\n0.1,0.2\n-0.3,0.4\n0.5,-0.6\n", encoding="utf-8")
    columns = run("datasets", "encrypt-upload", dataset["id"], str(keys), "--csv", str(csv_file))
    assert [c["label"] for c in columns] == ["age_z", "bp_z"]
    assert len(run("datasets", "ciphertexts", dataset["id"])) == 3

    job = run("jobs", "submit", project["id"], "mean", "-i", single[0]["id"])
    weighted = run(
        "jobs",
        "submit",
        project["id"],
        "linear_regression",
        "-i",
        columns[0]["id"],
        "-i",
        columns[1]["id"],
        "--args",
        json.dumps({"weights": [1.0, 2.0], "layout": "columns"}),
    )
    assert cli_env.drain() == ["succeeded", "succeeded"]
    assert run("jobs", "status", job["id"])["status"] == "succeeded"
    assert len(run("jobs", "list", "--status", "succeeded")) == 2
    out_file = tmp_path / "result.json"
    result = run("jobs", "result", job["id"], str(keys), "--out", str(out_file))
    assert result["values"][0] == pytest.approx(130.0, abs=1e-3)
    assert json.loads(out_file.read_text(encoding="utf-8"))[0] == pytest.approx(130.0, abs=1e-3)
    linear = run("jobs", "result", weighted["id"], str(keys))["values"]
    assert linear == pytest.approx([0.5, 0.5, -0.7], abs=1e-3)

    watch = runner.invoke(cli.app, ["jobs", "watch", job["id"]], catch_exceptions=False)
    assert "succeeded" in watch.output and "levels 1/2" in watch.output

    pending = run("jobs", "submit", project["id"], "sum", "-i", single[0]["id"])
    assert run("jobs", "cancel", pending["id"])["status"] == "cancelled"

    assert {o["name"] for o in run("operations")} >= {"mean"}
    assert len(run("parameter-sets")) == 17
    advice = run(
        "advise", "--operation", "logistic_regression", "--length", "3", "--args", json.dumps({"weights": [1, 2, 3]})
    )
    assert advice["params"]["coeff_mod_bit_sizes"] == [45, 30, 30, 30, 30, 45]
    assert any(e["action"] == "job.submitted" for e in run("audit", "list"))
    assert run("audit", "verify")["valid"] is True
    key = run("api-keys", "create", "ci", "--scope", "jobs:read")
    assert key["secret"].startswith("cc_")
    assert run("api-keys", "list")[0]["prefix"] == key["api_key"]["prefix"]
    assert run("api-keys", "revoke", key["api_key"]["id"])["revoked_at"]
    assert run("usage")["jobs_by_status"]["succeeded"] == 2

    login = run("login", "--email", email)
    assert login["role"] == "owner"
    runner.invoke(cli.app, ["logout"], catch_exceptions=False)
    assert not (cli.HOME / cli.SESSION_FILE).exists()


def test_cli_tables_and_api_key_env(cli_env: Stack, monkeypatch: pytest.MonkeyPatch) -> None:
    client = cli_env.client()
    client.register(f"t-{uuid.uuid4().hex[:6]}@example.com", PASSWORD, "Table Org")
    client.create_project("visible")
    secret = client.create_api_key("k", ["projects:read"])["secret"]
    monkeypatch.setenv("CC_API_KEY", secret)
    monkeypatch.setenv("CC_SERVER", "https://api.test")
    result = runner.invoke(cli.app, ["projects", "list"], catch_exceptions=False)
    assert result.exit_code == 0 and "visible" in result.output and "Projects" in result.output


def test_cli_errors(
    cli_env: Stack, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    result = runner.invoke(cli.app, ["projects", "list"])
    assert result.exit_code != 0 and "no server configured" in result.output
    bad = runner.invoke(cli.app, ["keys", "generate", str(tmp_path / "k"), "--profile", "weird"])
    assert bad.exit_code != 0
    run("keys", "generate", str(tmp_path / "k2"))
    monkeypatch.setenv("CC_SERVER", "https://api.test")
    both = runner.invoke(cli.app, ["datasets", "encrypt-upload", "x", str(tmp_path / "k2")])
    assert both.exit_code != 0 and "exactly one" in both.output
    nonjson = runner.invoke(cli.app, ["jobs", "submit", "p", "mean", "-i", "x", "--args", "{nope"])
    assert nonjson.exit_code != 0 and "JSON" in nonjson.output
    notobject = runner.invoke(cli.app, ["jobs", "submit", "p", "mean", "-i", "x", "--args", "[1]"])
    assert notobject.exit_code != 0 and "JSON object" in notobject.output

    # main() turns API and key errors into short messages and distinct exit codes
    def api_failure() -> None:
        raise ApiError(404, "not_found", "project not found", {"id": "p"}, "req-1")

    monkeypatch.setattr(cli, "app", api_failure)
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code == 2

    from ciphercompute_client.errors import KeyStoreError

    def key_failure() -> None:
        raise KeyStoreError("wrong passphrase")

    monkeypatch.setattr(cli, "app", key_failure)
    with pytest.raises(SystemExit) as excinfo:
        cli.main()
    assert excinfo.value.code == 3


def test_audit_verify_exit_code(cli_env: Stack, monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken:
        def verify_audit_chain(self) -> dict[str, Any]:
            return {"valid": False, "first_broken_seq": 7}

    monkeypatch.setattr(cli, "make_client", Broken)
    result = runner.invoke(cli.app, ["audit", "verify"])
    assert result.exit_code == 1 and "first_broken_seq" in result.output


def test_insecure_http_env_only_applies_to_localhost(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CC_INSECURE_HTTP", "1")
    runner.invoke(cli.app, ["--json", "operations"])  # sets global state; the call itself fails (no server)
    assert cli.state.transport.allow_insecure_http is True
    from ciphercompute_client.transport import check_base_url

    assert check_base_url("http://127.0.0.1:8000", cli.state.transport) == "http://127.0.0.1:8000"
    with pytest.raises(ValueError, match="https"):
        check_base_url("http://api.example.com", cli.state.transport)
