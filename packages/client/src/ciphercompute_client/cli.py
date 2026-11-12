"""``ciphercompute`` command-line interface — every SDK operation, scriptable.

Secrets never appear on the command line: passphrases and passwords are prompted for (or read
from ``CC_KEY_PASSPHRASE`` / ``CC_PASSWORD``), API keys come from ``CC_API_KEY``, and the login
session is stored in ``~/.ciphercompute/session.json`` with mode 0600.
"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Annotated, Any

import numpy as np
import typer
from rich.console import Console
from rich.table import Table

from ciphercompute_core import SecurityLevel

from .client import CipherComputeClient
from .errors import ApiError, KeyStoreError
from .keystore import KeyStore, _write_private
from .transport import TransportConfig

app = typer.Typer(
    help="CipherCompute: compute on encrypted data. Your secret key never leaves this machine.", no_args_is_help=True
)
keys_app = typer.Typer(help="Generate and inspect local CKKS key rings.", no_args_is_help=True)
projects_app = typer.Typer(help="Projects.", no_args_is_help=True)
bundles_app = typer.Typer(help="Public key bundles.", no_args_is_help=True)
datasets_app = typer.Typer(help="Datasets and ciphertexts.", no_args_is_help=True)
jobs_app = typer.Typer(help="Submit, watch and decrypt jobs.", no_args_is_help=True)
audit_app = typer.Typer(help="Audit log.", no_args_is_help=True)
apikeys_app = typer.Typer(help="API keys.", no_args_is_help=True)
for sub, name in (
    (keys_app, "keys"),
    (projects_app, "projects"),
    (bundles_app, "bundles"),
    (datasets_app, "datasets"),
    (jobs_app, "jobs"),
    (audit_app, "audit"),
    (apikeys_app, "api-keys"),
):
    app.add_typer(sub, name=name)

console = Console()
err_console = Console(stderr=True)

HOME = Path(os.environ.get("CC_HOME", Path.home() / ".ciphercompute"))
SESSION_FILE = "session.json"


class State:
    server: str | None = None
    transport: TransportConfig = TransportConfig()
    output_json: bool = False


state = State()


def _session_path() -> Path:
    return HOME / SESSION_FILE


def _load_session() -> dict[str, Any]:
    path = _session_path()
    if not path.is_file():
        return {}
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def _save_session(data: dict[str, Any]) -> None:
    HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = _session_path()
    if path.exists():
        path.unlink()
    _write_private(path, json.dumps(data).encode("utf-8"))


def make_client() -> CipherComputeClient:
    session = _load_session()
    server = state.server or os.environ.get("CC_SERVER") or session.get("server")
    if not server:
        raise typer.BadParameter("no server configured: pass --server or set CC_SERVER, or run `ciphercompute login`")
    api_key = os.environ.get("CC_API_KEY")
    return CipherComputeClient(
        server,
        api_key=api_key,
        access_token=None if api_key else session.get("access_token"),
        refresh_token=None if api_key else session.get("refresh_token"),
        transport_config=state.transport,
    )


def _persist_tokens(client: CipherComputeClient) -> None:
    if client.api_key or not client.access_token:
        return
    session = _load_session()
    if session.get("access_token") != client.access_token:
        session.update(access_token=client.access_token, refresh_token=client.refresh_token)
        _save_session(session)


def emit(data: Any, *, columns: list[str] | None = None, title: str | None = None) -> None:
    if state.output_json or columns is None:
        console.print_json(json.dumps(data, default=str))
        return
    rows = data if isinstance(data, list) else [data]
    table = Table(title=title)
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*[str(row.get(col, "")) for col in columns])
    console.print(table)


def _passphrase(confirm: bool = False) -> str:
    env = os.environ.get("CC_KEY_PASSPHRASE")
    if env:
        return env
    return str(typer.prompt("Key passphrase", hide_input=True, confirmation_prompt=confirm))


def _open_keys(path: Path) -> KeyStore:
    meta = KeyStore.metadata(path)
    return KeyStore.open(path, passphrase=_passphrase() if meta.get("encrypted", True) else None)


def _parse_json(value: str | None, what: str) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except ValueError as exc:
        raise typer.BadParameter(f"{what} must be JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise typer.BadParameter(f"{what} must be a JSON object")
    return parsed


@app.callback()
def main_options(
    server: Annotated[str | None, typer.Option(help="API base URL (or CC_SERVER).")] = None,
    ca_file: Annotated[str | None, typer.Option(help="Extra CA bundle for a private PKI.")] = None,
    client_cert: Annotated[str | None, typer.Option(help="Client certificate (PEM) for mutual TLS.")] = None,
    client_key: Annotated[str | None, typer.Option(help="Client private key (PEM) for mutual TLS.")] = None,
    insecure_http: Annotated[
        bool, typer.Option(help="Allow http:// to localhost (development only; or CC_INSECURE_HTTP=1).")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    state.server = server
    state.output_json = json_output
    state.transport = TransportConfig(
        ca_file=ca_file,
        client_cert=client_cert,
        client_key=client_key,
        # still refused for anything but localhost (transport.check_base_url)
        allow_insecure_http=insecure_http or os.environ.get("CC_INSECURE_HTTP") == "1",
    )


# ----- keys ------------------------------------------------------------------------------------


@keys_app.command("generate")
def keys_generate(
    path: Annotated[Path, typer.Argument(help="Directory for the new key ring (must be empty).")],
    degree: Annotated[int, typer.Option(help="poly_modulus_degree: 8192, 16384 or 32768.")] = 8192,
    security: Annotated[int, typer.Option(help="Security level in bits: 128, 192 or 256.")] = 128,
    profile: Annotated[str, typer.Option(help="'balanced' (precision) or 'deep' (more levels).")] = "balanced",
    no_passphrase: Annotated[
        bool, typer.Option(help="Store the secret key unencrypted (throwaway keys only).")
    ] = False,
) -> None:
    """Generate a CKKS key ring locally. The secret key is written encrypted and never uploaded."""
    if profile not in ("balanced", "deep"):
        raise typer.BadParameter("profile must be 'balanced' or 'deep'")
    passphrase = None if no_passphrase else _passphrase(confirm=True)
    store = KeyStore.create(
        path,
        poly_modulus_degree=degree,
        security_level=SecurityLevel(security),
        profile=profile,  # type: ignore[arg-type]
        passphrase=passphrase,
        allow_unencrypted=no_passphrase,
    )
    emit(
        {
            "path": str(store.path),
            "ring_id": store.ring_id,
            "params": store.params.describe(),
            "encrypted": not no_passphrase,
        }
    )


@keys_app.command("info")
def keys_info(path: Annotated[Path, typer.Argument()]) -> None:
    """Show key ring metadata without unlocking the secret key."""
    emit(KeyStore.metadata(path))


# ----- auth ------------------------------------------------------------------------------------


@app.command()
def register(
    email: Annotated[str, typer.Option(prompt=True)],
    organization: Annotated[str, typer.Option(prompt=True)],
) -> None:
    """Create an account and organization, and log in."""
    password = os.environ.get("CC_PASSWORD") or typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    client = make_client()
    tokens = client.register(email, password, organization)
    _save_session(
        {
            "server": client._transport.base_url,
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
        }
    )
    emit({"organization_id": tokens["organization_id"], "role": tokens["role"]})


@app.command()
def login(
    email: Annotated[str, typer.Option(prompt=True)],
    organization_id: Annotated[str | None, typer.Option(help="Organization to log into.")] = None,
) -> None:
    """Log in and store the session (mode 0600)."""
    password = os.environ.get("CC_PASSWORD") or typer.prompt("Password", hide_input=True)
    client = make_client()
    tokens = client.login(email, password, organization_id)
    _save_session(
        {
            "server": client._transport.base_url,
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
        }
    )
    emit({"organization_id": tokens["organization_id"], "role": tokens["role"]})


@app.command()
def logout() -> None:
    """Revoke the session server-side and delete it locally."""
    client = make_client()
    try:
        client.logout()
    finally:
        _session_path().unlink(missing_ok=True)
    console.print("logged out")


@app.command()
def whoami() -> None:
    client = make_client()
    emit(client.me())
    _persist_tokens(client)


# ----- projects / bundles / datasets ------------------------------------------------------------


@projects_app.command("create")
def projects_create(name: str, description: Annotated[str, typer.Option()] = "") -> None:
    emit(make_client().create_project(name, description), columns=["id", "name", "description"])


@projects_app.command("list")
def projects_list() -> None:
    emit(make_client().list_projects(), columns=["id", "name", "created_at"], title="Projects")


@bundles_app.command("upload")
def bundles_upload(project_id: str, keys_path: Annotated[Path, typer.Argument(help="Key ring directory.")]) -> None:
    """Upload the public bundle of a key ring (reads public.ccpk; the secret key is not unlocked)."""
    emit(
        make_client().upload_key_bundle(project_id, KeyStore.public_bundle_bytes(keys_path)),
        columns=["id", "ring_id", "status", "size_bytes"],
    )


@bundles_app.command("list")
def bundles_list(project_id: str) -> None:
    emit(
        make_client().list_key_bundles(project_id),
        columns=["id", "ring_id", "status", "created_at"],
        title="Key bundles",
    )


@datasets_app.command("create")
def datasets_create(project_id: str, name: str, key_bundle_id: str) -> None:
    emit(make_client().create_dataset(project_id, name, key_bundle_id), columns=["id", "name", "key_bundle_id"])


@datasets_app.command("list")
def datasets_list(project_id: str) -> None:
    emit(make_client().list_datasets(project_id), columns=["id", "name", "created_at"], title="Datasets")


@datasets_app.command("ciphertexts")
def datasets_ciphertexts(dataset_id: str) -> None:
    emit(
        make_client().list_ciphertexts(dataset_id),
        columns=["id", "label", "status", "length", "size_bytes"],
        title="Ciphertexts",
    )


def _read_csv(path: Path) -> tuple[list[str], np.ndarray]:
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        rows = [[float(v) for v in row] for row in reader if row]
    return header, np.asarray(rows, dtype=np.float64)


@datasets_app.command("encrypt-upload")
def datasets_encrypt_upload(
    dataset_id: str,
    keys_path: Annotated[Path, typer.Argument(help="Key ring directory (public key is enough).")],
    values: Annotated[str | None, typer.Option(help="Comma-separated numbers, e.g. '1.5,2,3'.")] = None,
    csv_file: Annotated[
        Path | None, typer.Option("--csv", help="CSV with a header row; one ciphertext per column.")
    ] = None,
    label: Annotated[str, typer.Option(help="Label for --values.")] = "values",
    pad_to: Annotated[int | None, typer.Option(help="Pad to this length to hide the true size.")] = None,
) -> None:
    """Encrypt locally (public key only) and upload ciphertexts."""
    from ciphercompute_core import PublicKeyBundle

    bundle = PublicKeyBundle.load(KeyStore.public_bundle_bytes(keys_path))
    client = make_client()
    if (values is None) == (csv_file is None):
        raise typer.BadParameter("give exactly one of --values or --csv")
    if values is not None:
        nums = [float(v) for v in values.split(",") if v.strip()]
        out = [client.encrypt_and_upload(dataset_id, bundle, nums, label=label, pad_to=pad_to)]
    elif csv_file is not None:
        header, matrix = _read_csv(csv_file)
        out = client.encrypt_columns_and_upload(dataset_id, bundle, matrix, labels=header)
    emit(out, columns=["id", "label", "length", "fingerprint"], title="Uploaded ciphertexts")


# ----- jobs ------------------------------------------------------------------------------------


@jobs_app.command("submit")
def jobs_submit(
    project_id: str,
    operation: str,
    inputs: Annotated[list[str], typer.Option("--input", "-i", help="Ciphertext id (repeat for several, in order).")],
    args: Annotated[str | None, typer.Option(help="Operation arguments as JSON.")] = None,
    idempotency_key: Annotated[str | None, typer.Option(help="Reuse to make retries safe.")] = None,
) -> None:
    job = make_client().submit_job(
        project_id, operation, inputs, _parse_json(args, "--args"), idempotency_key=idempotency_key
    )
    emit(job, columns=["id", "operation", "status", "manifest_hash"])


@jobs_app.command("status")
def jobs_status(job_id: str) -> None:
    emit(make_client().get_job(job_id))


@jobs_app.command("list")
def jobs_list(
    project_id: Annotated[str | None, typer.Option()] = None, status: Annotated[str | None, typer.Option()] = None
) -> None:
    emit(
        make_client().list_jobs(project_id=project_id, status=status),
        columns=["id", "operation", "status", "created_at"],
        title="Jobs",
    )


@jobs_app.command("watch")
def jobs_watch(job_id: str) -> None:
    """Follow a job live (Server-Sent Events)."""
    for update in make_client().events(job_id):
        report = update.get("depth_report") or {}
        console.print(
            f"{update['status']:<10} levels {report.get('levels_consumed', '?')}/{report.get('levels_total', '?')}"
        )


@jobs_app.command("result")
def jobs_result(
    job_id: str,
    keys_path: Annotated[Path, typer.Argument(help="Key ring directory (secret key needed to decrypt).")],
    wait: Annotated[bool, typer.Option(help="Wait for the job to finish.")] = True,
    out: Annotated[Path | None, typer.Option(help="Write the decrypted values to this JSON file.")] = None,
) -> None:
    """Download the encrypted result and decrypt it locally."""
    client = make_client()
    store = _open_keys(keys_path)
    if wait:
        client.wait(job_id)
    values = client.decrypt_result(job_id, store.ring).tolist()
    if out:
        out.write_text(json.dumps(values), encoding="utf-8")
    emit({"job_id": job_id, "values": values})


@jobs_app.command("cancel")
def jobs_cancel(job_id: str) -> None:
    emit(make_client().cancel_job(job_id), columns=["id", "status"])


# ----- catalog / audit / keys / usage ------------------------------------------------------------


@app.command()
def operations() -> None:
    """List supported homomorphic operations."""
    emit(make_client().operations(), columns=["name", "summary", "min_inputs", "max_inputs"], title="Operations")


@app.command("parameter-sets")
def parameter_sets() -> None:
    emit(
        make_client().parameter_sets(),
        columns=["profile", "poly_modulus_degree", "security_level", "depth", "scale_bits", "slots"],
        title="Parameter sets",
    )


@app.command()
def advise(
    operation: Annotated[str, typer.Option()],
    length: Annotated[int, typer.Option(help="Input vector length.")],
    args: Annotated[str | None, typer.Option(help="Operation arguments as JSON.")] = None,
    security: Annotated[int, typer.Option()] = 128,
    min_precision_bits: Annotated[int, typer.Option()] = 0,
) -> None:
    """Recommend CKKS parameters for an operation."""
    result = make_client().advise(
        [(operation, _parse_json(args, "--args"))],
        [length],
        security_level=security,
        min_precision_bits=min_precision_bits,
    )
    emit(result)


@audit_app.command("list")
def audit_list(
    action: Annotated[str | None, typer.Option()] = None, limit: Annotated[int, typer.Option()] = 50
) -> None:
    emit(
        make_client().audit_events(action=action, limit=limit),
        columns=["seq", "occurred_at", "action", "actor_type", "resource_id"],
        title="Audit",
    )


@audit_app.command("verify")
def audit_verify() -> None:
    """Re-walk the organization's hash chain; exits 1 if it is broken."""
    result = make_client().verify_audit_chain()
    emit(result)
    if not result["valid"]:
        raise typer.Exit(1)


@apikeys_app.command("create")
def apikeys_create(
    name: str,
    scopes: Annotated[list[str], typer.Option("--scope", help="Repeat for several scopes.")],
    expires_in_days: Annotated[int | None, typer.Option()] = None,
) -> None:
    """Create an API key. The secret is printed once."""
    emit(make_client().create_api_key(name, scopes, expires_in_days))


@apikeys_app.command("list")
def apikeys_list() -> None:
    emit(make_client().list_api_keys(), columns=["id", "name", "prefix", "role", "revoked_at"], title="API keys")


@apikeys_app.command("revoke")
def apikeys_revoke(key_id: str) -> None:
    emit(make_client().revoke_api_key(key_id), columns=["id", "prefix", "revoked_at"])


@app.command()
def usage(days: Annotated[int, typer.Option()] = 30) -> None:
    emit(make_client().usage(days))


def main() -> None:
    try:
        app()
    except ApiError as exc:
        err_console.print(
            f"[red]error[/red] {exc.status_code} {exc.code}: {exc.message}"
            + (f" (request {exc.request_id})" if exc.request_id else "")
        )
        if exc.details:
            err_console.print_json(json.dumps(exc.details, default=str))
        raise SystemExit(2) from None
    except KeyStoreError as exc:
        err_console.print(f"[red]key error[/red] {exc}")
        raise SystemExit(3) from None
