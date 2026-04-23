from __future__ import annotations

import json
from pathlib import Path
import sys

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import typer

from coordinator.chainattest_coordinator.service import CoordinatorService


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
