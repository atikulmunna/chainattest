from dataclasses import dataclass


@dataclass
class CoordinatorStatus:
    status: str = "idle"
    queue_depth: int = 0
    pending_signature_requests: int = 0
    proof_jobs_in_progress: int = 0


class CoordinatorService:
    def __init__(self) -> None:
        self.status = CoordinatorStatus()

    def health(self) -> dict:
        return {
            "status": self.status.status,
            "queue_depth": self.status.queue_depth,
            "pending_signature_requests": self.status.pending_signature_requests,
            "proof_jobs_in_progress": self.status.proof_jobs_in_progress,
        }

