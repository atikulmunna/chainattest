from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from uuid import uuid4


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class CoordinatorJob:
    job_id: str
    job_kind: str
    input_path: str
    output_path: str | None = None
    state: JobState = JobState.QUEUED
    error: str | None = None


@dataclass
class CoordinatorStatus:
    status: str = "idle"
    queue_depth: int = 0
    pending_signature_requests: int = 0
    proof_jobs_in_progress: int = 0
    completed_jobs: int = 0
    failed_jobs: int = 0


class CoordinatorService:
    def __init__(self) -> None:
        self.status = CoordinatorStatus()
        self.jobs: dict[str, CoordinatorJob] = {}
        self.job_order: list[str] = []

    def health(self) -> dict:
        return asdict(self.status)

    def submit_job(self, job_kind: str, input_path: Path, output_path: Path | None = None) -> CoordinatorJob:
        job = CoordinatorJob(
            job_id=f"job-{uuid4()}",
            job_kind=job_kind,
            input_path=str(input_path),
            output_path=str(output_path) if output_path else None,
        )
        self.jobs[job.job_id] = job
        self.job_order.append(job.job_id)
        self.status.queue_depth += 1
        if self.status.status == "idle":
            self.status.status = "active"
        return job

    def start_job(self, job_id: str) -> CoordinatorJob:
        job = self.jobs[job_id]
        if job.state == JobState.QUEUED:
            self.status.queue_depth -= 1
            self.status.proof_jobs_in_progress += 1
        job.state = JobState.RUNNING
        return job

    def complete_job(self, job_id: str) -> CoordinatorJob:
        job = self.jobs[job_id]
        if job.state == JobState.RUNNING:
            self.status.proof_jobs_in_progress -= 1
        job.state = JobState.COMPLETED
        self.status.completed_jobs += 1
        self._refresh_status()
        return job

    def fail_job(self, job_id: str, error: str) -> CoordinatorJob:
        job = self.jobs[job_id]
        if job.state == JobState.RUNNING:
            self.status.proof_jobs_in_progress -= 1
        elif job.state == JobState.QUEUED:
            self.status.queue_depth -= 1
        job.state = JobState.FAILED
        job.error = error
        self.status.failed_jobs += 1
        self._refresh_status()
        return job

    def get_job(self, job_id: str) -> dict:
        return asdict(self.jobs[job_id])

    def list_jobs(self) -> list[dict]:
        return [asdict(self.jobs[job_id]) for job_id in self.job_order]

    def _refresh_status(self) -> None:
        if self.status.queue_depth == 0 and self.status.proof_jobs_in_progress == 0:
            self.status.status = "idle"
