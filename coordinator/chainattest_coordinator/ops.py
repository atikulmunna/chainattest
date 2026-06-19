from __future__ import annotations

import json
from pathlib import Path
import sys

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import typer

from coordinator.chainattest_coordinator.service import CoordinatorService, RevocationBundleRequest


app = typer.Typer(help="ChainAttest coordinator operator commands.")


def _print_json(payload: object) -> None:
    typer.echo(json.dumps(payload, indent=2))


def _service(
    db_path: Path | None,
    state_path: Path | None,
    audit_log_path: Path | None,
) -> CoordinatorService:
    return CoordinatorService(
        state_path=state_path,
        audit_log_path=audit_log_path,
        db_path=db_path,
    )


def _parse_csv(value: str | None) -> list[str]:
    if value is None:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def _build_revocation_request(
    registered_package_path: Path,
    source_tx_id: str,
    source_block_number: int,
    source_block_hash: str,
    output_dir: Path,
    destination_rpc_url: str | None,
    destination_verifier_address: str | None,
    destination_submitter_private_key: str | None,
    destination_submitter_key_env: str | None,
    signer_service_url: str | None,
    signer_service_token_env: str | None,
    destination_submitter_command: str | None,
    destination_submitter_auth_token_env: str | None,
    destination_chain_id: int | None,
    committee_verifier_address: str | None,
    committee_private_keys: str | None,
    committee_key_envs: str | None,
    committee_signer_command: str | None,
    committee_signer_auth_token_env: str | None,
    committee_threshold: int | None,
    signatures_file: Path | None,
) -> RevocationBundleRequest:
    return RevocationBundleRequest(
        registered_package_path=registered_package_path,
        source_tx_id=source_tx_id,
        source_block_number=source_block_number,
        source_block_hash=source_block_hash,
        output_dir=output_dir,
        destination_chain_id=destination_chain_id,
        destination_rpc_url=destination_rpc_url,
        destination_submitter_private_key=destination_submitter_private_key,
        destination_submitter_key_env=destination_submitter_key_env,
        signer_service_url=signer_service_url,
        signer_service_token_env=signer_service_token_env,
        destination_submitter_command=_parse_csv(destination_submitter_command),
        destination_submitter_auth_token_env=destination_submitter_auth_token_env,
        destination_verifier_address=destination_verifier_address,
        committee_verifier_address=committee_verifier_address,
        committee_private_keys=_parse_csv(committee_private_keys),
        committee_key_envs=_parse_csv(committee_key_envs),
        committee_signer_command=_parse_csv(committee_signer_command),
        committee_signer_auth_token_env=committee_signer_auth_token_env,
        committee_threshold=committee_threshold,
        signatures_file=signatures_file,
    )


@app.command("health")
def health(
    db_path: Path | None = typer.Option(None, "--db-path", help="Coordinator SQLite database path"),
    state_path: Path | None = typer.Option(None, "--state-path", help="Legacy/shadow coordinator state file"),
    audit_log_path: Path | None = typer.Option(None, help="Optional audit log path"),
) -> None:
    service = _service(db_path, state_path, audit_log_path)
    _print_json(service.health())


@app.command("list-jobs")
def list_jobs(
    db_path: Path | None = typer.Option(None, "--db-path", help="Coordinator SQLite database path"),
    state_path: Path | None = typer.Option(None, "--state-path", help="Legacy/shadow coordinator state file"),
    audit_log_path: Path | None = typer.Option(None, help="Optional audit log path"),
    state_filter: str | None = typer.Option(None, "--state", help="Optional job state filter"),
) -> None:
    service = _service(db_path, state_path, audit_log_path)
    jobs = service.list_jobs()
    if state_filter is not None:
        jobs = [job for job in jobs if job["state"] == state_filter]
    _print_json(jobs)


@app.command("show-job")
def show_job(
    job_id: str = typer.Argument(..., help="Coordinator job id"),
    db_path: Path | None = typer.Option(None, "--db-path", help="Coordinator SQLite database path"),
    state_path: Path | None = typer.Option(None, "--state-path", help="Legacy/shadow coordinator state file"),
    audit_log_path: Path | None = typer.Option(None, help="Optional audit log path"),
) -> None:
    service = _service(db_path, state_path, audit_log_path)
    _print_json(service.get_job(job_id))


@app.command("resume")
def resume(
    db_path: Path | None = typer.Option(None, "--db-path", help="Coordinator SQLite database path"),
    state_path: Path | None = typer.Option(None, "--state-path", help="Legacy/shadow coordinator state file"),
    audit_log_path: Path | None = typer.Option(None, help="Optional audit log path"),
) -> None:
    service = _service(db_path, state_path, audit_log_path)
    _print_json(service.resume_pending_jobs())


@app.command("retry-failed")
def retry_failed(
    db_path: Path | None = typer.Option(None, "--db-path", help="Coordinator SQLite database path"),
    state_path: Path | None = typer.Option(None, "--state-path", help="Legacy/shadow coordinator state file"),
    audit_log_path: Path | None = typer.Option(None, help="Optional audit log path"),
) -> None:
    service = _service(db_path, state_path, audit_log_path)
    _print_json(service.retry_failed_jobs())


@app.command("revoke-attestation")
def revoke_attestation(
    registered_package_path: Path = typer.Argument(..., help="Previously rendered attestation package JSON"),
    source_tx_id: str = typer.Option(..., help="Revocation source transaction id as bytes32 hex"),
    source_block_number: int = typer.Option(..., help="Revocation source block number"),
    source_block_hash: str = typer.Option(..., help="Revocation source block hash as bytes32 hex"),
    output_dir: Path = typer.Option(..., help="Output directory for revoke artifacts"),
    destination_rpc_url: str | None = typer.Option(None, help="Destination RPC URL for optional submission"),
    destination_verifier_address: str | None = typer.Option(None, help="SemanticVerifier destination address"),
    destination_submitter_private_key: str | None = typer.Option(None, help="Destination submitter private key"),
    destination_submitter_key_env: str | None = typer.Option(None, help="Destination submitter private-key environment variable"),
    signer_service_url: str | None = typer.Option(None, help="HTTP signer service URL"),
    signer_service_token_env: str | None = typer.Option(None, help="HTTP signer bearer-token environment variable"),
    destination_submitter_command: str | None = typer.Option(None, help="Comma-separated destination submitter command override"),
    destination_submitter_auth_token_env: str | None = typer.Option(None, help="Submitter command auth token environment variable"),
    destination_chain_id: int | None = typer.Option(None, help="Destination chain id for committee approvals"),
    committee_verifier_address: str | None = typer.Option(None, help="CommitteeAuthAdapter destination address"),
    committee_private_keys: str | None = typer.Option(None, help="Comma-separated committee private keys"),
    committee_key_envs: str | None = typer.Option(None, help="Comma-separated committee private-key environment variables"),
    committee_signer_command: str | None = typer.Option(None, help="Comma-separated committee signer command override"),
    committee_signer_auth_token_env: str | None = typer.Option(None, help="Committee signer auth token environment variable"),
    committee_threshold: int | None = typer.Option(None, help="Committee approval threshold"),
    signatures_file: Path | None = typer.Option(None, help="Existing committee signature JSON"),
    wait_for_receipt: bool = typer.Option(True, "--wait-for-receipt/--no-wait-for-receipt", help="Wait for destination receipt when submitting"),
    receipt_timeout_seconds: float = typer.Option(30.0, help="Receipt wait timeout in seconds"),
    poll_interval_seconds: float = typer.Option(1.0, help="Receipt polling interval in seconds"),
    db_path: Path | None = typer.Option(None, "--db-path", help="Coordinator SQLite database path"),
    state_path: Path | None = typer.Option(None, "--state-path", help="Legacy/shadow coordinator state file"),
    audit_log_path: Path | None = typer.Option(None, help="Optional audit log path"),
) -> None:
    service = _service(db_path, state_path, audit_log_path)
    request = _build_revocation_request(
        registered_package_path=registered_package_path,
        source_tx_id=source_tx_id,
        source_block_number=source_block_number,
        source_block_hash=source_block_hash,
        output_dir=output_dir,
        destination_rpc_url=destination_rpc_url,
        destination_verifier_address=destination_verifier_address,
        destination_submitter_private_key=destination_submitter_private_key,
        destination_submitter_key_env=destination_submitter_key_env,
        signer_service_url=signer_service_url,
        signer_service_token_env=signer_service_token_env,
        destination_submitter_command=destination_submitter_command,
        destination_submitter_auth_token_env=destination_submitter_auth_token_env,
        destination_chain_id=destination_chain_id,
        committee_verifier_address=committee_verifier_address,
        committee_private_keys=committee_private_keys,
        committee_key_envs=committee_key_envs,
        committee_signer_command=committee_signer_command,
        committee_signer_auth_token_env=committee_signer_auth_token_env,
        committee_threshold=committee_threshold,
        signatures_file=signatures_file,
    )
    _print_json(
        service.orchestrate_attestation_revoke(
            request,
            wait_for_receipt=wait_for_receipt,
            receipt_timeout_seconds=receipt_timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
        )
    )


@app.command("revoke-eval")
def revoke_eval(
    registered_package_path: Path = typer.Argument(..., help="Previously rendered eval package JSON"),
    source_tx_id: str = typer.Option(..., help="Revocation source transaction id as bytes32 hex"),
    source_block_number: int = typer.Option(..., help="Revocation source block number"),
    source_block_hash: str = typer.Option(..., help="Revocation source block hash as bytes32 hex"),
    output_dir: Path = typer.Option(..., help="Output directory for revoke artifacts"),
    destination_rpc_url: str | None = typer.Option(None, help="Destination RPC URL for optional submission"),
    destination_verifier_address: str | None = typer.Option(None, help="EvalThresholdVerifier destination address"),
    destination_submitter_private_key: str | None = typer.Option(None, help="Destination submitter private key"),
    destination_submitter_key_env: str | None = typer.Option(None, help="Destination submitter private-key environment variable"),
    signer_service_url: str | None = typer.Option(None, help="HTTP signer service URL"),
    signer_service_token_env: str | None = typer.Option(None, help="HTTP signer bearer-token environment variable"),
    destination_submitter_command: str | None = typer.Option(None, help="Comma-separated destination submitter command override"),
    destination_submitter_auth_token_env: str | None = typer.Option(None, help="Submitter command auth token environment variable"),
    destination_chain_id: int | None = typer.Option(None, help="Destination chain id for committee approvals"),
    committee_verifier_address: str | None = typer.Option(None, help="CommitteeAuthAdapter destination address"),
    committee_private_keys: str | None = typer.Option(None, help="Comma-separated committee private keys"),
    committee_key_envs: str | None = typer.Option(None, help="Comma-separated committee private-key environment variables"),
    committee_signer_command: str | None = typer.Option(None, help="Comma-separated committee signer command override"),
    committee_signer_auth_token_env: str | None = typer.Option(None, help="Committee signer auth token environment variable"),
    committee_threshold: int | None = typer.Option(None, help="Committee approval threshold"),
    signatures_file: Path | None = typer.Option(None, help="Existing committee signature JSON"),
    wait_for_receipt: bool = typer.Option(True, "--wait-for-receipt/--no-wait-for-receipt", help="Wait for destination receipt when submitting"),
    receipt_timeout_seconds: float = typer.Option(30.0, help="Receipt wait timeout in seconds"),
    poll_interval_seconds: float = typer.Option(1.0, help="Receipt polling interval in seconds"),
    db_path: Path | None = typer.Option(None, "--db-path", help="Coordinator SQLite database path"),
    state_path: Path | None = typer.Option(None, "--state-path", help="Legacy/shadow coordinator state file"),
    audit_log_path: Path | None = typer.Option(None, help="Optional audit log path"),
) -> None:
    service = _service(db_path, state_path, audit_log_path)
    request = _build_revocation_request(
        registered_package_path=registered_package_path,
        source_tx_id=source_tx_id,
        source_block_number=source_block_number,
        source_block_hash=source_block_hash,
        output_dir=output_dir,
        destination_rpc_url=destination_rpc_url,
        destination_verifier_address=destination_verifier_address,
        destination_submitter_private_key=destination_submitter_private_key,
        destination_submitter_key_env=destination_submitter_key_env,
        signer_service_url=signer_service_url,
        signer_service_token_env=signer_service_token_env,
        destination_submitter_command=destination_submitter_command,
        destination_submitter_auth_token_env=destination_submitter_auth_token_env,
        destination_chain_id=destination_chain_id,
        committee_verifier_address=committee_verifier_address,
        committee_private_keys=committee_private_keys,
        committee_key_envs=committee_key_envs,
        committee_signer_command=committee_signer_command,
        committee_signer_auth_token_env=committee_signer_auth_token_env,
        committee_threshold=committee_threshold,
        signatures_file=signatures_file,
    )
    _print_json(
        service.orchestrate_eval_revoke(
            request,
            wait_for_receipt=wait_for_receipt,
            receipt_timeout_seconds=receipt_timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
        )
    )


@app.command("tail-audit")
def tail_audit(
    db_path: Path | None = typer.Option(None, "--db-path", help="Coordinator SQLite database path"),
    state_path: Path | None = typer.Option(None, "--state-path", help="Legacy/shadow coordinator state file"),
    audit_log_path: Path | None = typer.Option(None, help="Coordinator or signer audit log path"),
    limit: int = typer.Option(20, help="Maximum records to return"),
    event_type: str | None = typer.Option(None, help="Optional event type filter"),
) -> None:
    if db_path is not None or state_path is not None:
        service = _service(db_path, state_path, audit_log_path)
        _print_json(service.tail_audit_events(limit=limit, event_type=event_type))
        return

    if audit_log_path is None or not audit_log_path.exists():
        _print_json([])
        return

    records = [
        json.loads(line)
        for line in audit_log_path.read_text().splitlines()
        if line.strip()
    ]
    if event_type is not None:
        records = [record for record in records if record.get("event_type") == event_type]
    _print_json(records[-limit:])


if __name__ == "__main__":
    app()
