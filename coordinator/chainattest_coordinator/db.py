from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
import time
from typing import Any


class CoordinatorDatabase:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    job_kind TEXT NOT NULL,
                    input_path TEXT NOT NULL,
                    output_path TEXT,
                    state TEXT NOT NULL,
                    error TEXT,
                    attempts INTEGER NOT NULL,
                    tx_hash TEXT,
                    metadata_json TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS job_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_timestamp INTEGER NOT NULL,
                    correlation_id TEXT,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS submission_attempts (
                    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    attempt_no INTEGER NOT NULL,
                    tx_hash TEXT,
                    destination_rpc_url TEXT,
                    verifier_address TEXT,
                    error_kind TEXT,
                    correlation_id TEXT,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS nonces (
                    nonce TEXT PRIMARY KEY,
                    purpose TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                """
            )

    def has_jobs(self) -> bool:
        with self._connection() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM jobs").fetchone()
        return int(row["count"]) > 0

    def upsert_jobs(self, jobs: list[dict[str, Any]]) -> None:
        with self._connection() as connection:
            connection.executemany(
                """
                INSERT INTO jobs (
                    job_id, job_kind, input_path, output_path, state, error, attempts, tx_hash,
                    metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    job_kind=excluded.job_kind,
                    input_path=excluded.input_path,
                    output_path=excluded.output_path,
                    state=excluded.state,
                    error=excluded.error,
                    attempts=excluded.attempts,
                    tx_hash=excluded.tx_hash,
                    metadata_json=excluded.metadata_json,
                    created_at=excluded.created_at,
                    updated_at=excluded.updated_at
                """,
                [
                    (
                        job["job_id"],
                        job["job_kind"],
                        job["input_path"],
                        job.get("output_path"),
                        job["state"],
                        job.get("error"),
                        int(job["attempts"]),
                        job.get("tx_hash"),
                        json.dumps(job.get("metadata", {})),
                        int(job["created_at"]),
                        int(job["updated_at"]),
                    )
                    for job in jobs
                ],
            )

    def load_jobs(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM jobs ORDER BY created_at ASC, rowid ASC"
            ).fetchall()
        jobs: list[dict[str, Any]] = []
        for row in rows:
            jobs.append(
                {
                    "job_id": row["job_id"],
                    "job_kind": row["job_kind"],
                    "input_path": row["input_path"],
                    "output_path": row["output_path"],
                    "state": row["state"],
                    "error": row["error"],
                    "attempts": int(row["attempts"]),
                    "tx_hash": row["tx_hash"],
                    "metadata": json.loads(row["metadata_json"]) if row["metadata_json"] else {},
                    "created_at": int(row["created_at"]),
                    "updated_at": int(row["updated_at"]),
                }
            )
        return jobs

    def insert_event(
        self,
        job_id: str,
        event_type: str,
        payload: dict[str, Any],
        correlation_id: str | None = None,
        event_timestamp: int | None = None,
    ) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO job_events (job_id, event_type, event_timestamp, correlation_id, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    event_type,
                    int(event_timestamp or time.time()),
                    correlation_id,
                    json.dumps(payload),
                ),
            )

    def tail_events(self, limit: int = 20, event_type: str | None = None) -> list[dict[str, Any]]:
        query = """
            SELECT event_id, job_id, event_type, event_timestamp, correlation_id, payload_json
            FROM job_events
        """
        params: list[Any] = []
        if event_type is not None:
            query += " WHERE event_type = ?"
            params.append(event_type)
        query += " ORDER BY event_id DESC LIMIT ?"
        params.append(limit)

        with self._connection() as connection:
            rows = connection.execute(query, params).fetchall()

        events = []
        for row in reversed(rows):
            payload = json.loads(row["payload_json"]) if row["payload_json"] else {}
            events.append(
                {
                    "event_id": int(row["event_id"]),
                    "job_id": row["job_id"],
                    "event_type": row["event_type"],
                    "timestamp": int(row["event_timestamp"]),
                    "correlation_id": row["correlation_id"],
                    **payload,
                }
            )
        return events

    def insert_submission_attempt(
        self,
        job_id: str,
        attempt_no: int,
        tx_hash: str | None,
        destination_rpc_url: str | None,
        verifier_address: str | None,
        error_kind: str | None,
        correlation_id: str | None,
    ) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO submission_attempts (
                    job_id, attempt_no, tx_hash, destination_rpc_url, verifier_address,
                    error_kind, correlation_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    int(attempt_no),
                    tx_hash,
                    destination_rpc_url,
                    verifier_address,
                    error_kind,
                    correlation_id,
                    int(time.time()),
                ),
            )

    def list_submission_attempts(self, job_id: str) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT attempt_id, job_id, attempt_no, tx_hash, destination_rpc_url, verifier_address,
                       error_kind, correlation_id, created_at
                FROM submission_attempts
                WHERE job_id = ?
                ORDER BY attempt_id ASC
                """,
                (job_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def remember_nonce(self, nonce: str, purpose: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO nonces (nonce, purpose, created_at) VALUES (?, ?, ?)",
                (nonce, purpose, int(time.time())),
            )

    def has_nonce(self, nonce: str) -> bool:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM nonces WHERE nonce = ? LIMIT 1",
                (nonce,),
            ).fetchone()
        return row is not None

    def purge_nonces_older_than(self, min_created_at: int) -> None:
        with self._connection() as connection:
            connection.execute("DELETE FROM nonces WHERE created_at < ?", (int(min_created_at),))

    def migrate_legacy_files(self, state_path: Path | None, audit_log_path: Path | None) -> None:
        if self.has_jobs():
            return

        if state_path is not None and state_path.exists():
            payload = json.loads(state_path.read_text())
            raw_jobs = payload.get("jobs", [])
            for job in raw_jobs:
                if isinstance(job.get("metadata"), str):
                    job["metadata"] = json.loads(job["metadata"])
            self.upsert_jobs(raw_jobs)

        if audit_log_path is not None and audit_log_path.exists():
            for line in audit_log_path.read_text().splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                job_id = record.get("job_id")
                event_type = record.get("event_type")
                if job_id is None or event_type is None:
                    continue
                payload = {
                    key: value
                    for key, value in record.items()
                    if key not in {"timestamp", "event_type", "job_id", "correlation_id"}
                }
                self.insert_event(
                    job_id=job_id,
                    event_type=event_type,
                    payload=payload,
                    correlation_id=record.get("correlation_id"),
                    event_timestamp=record.get("timestamp"),
                )
