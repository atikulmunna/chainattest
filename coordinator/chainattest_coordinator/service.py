from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_ENTRYPOINT = REPO_ROOT / "cli" / "chain_attest" / "main.py"


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
class AttestationBundleRequest:
    model_path: Path
    metadata_path: Path
    training_path: Path
    dataset_path: Path
    owner: str
    weights_root: int
    parent_attestation_id: int
    attestation_id: int
    registered_at_block: int
    path_elements: list[int]
    path_indices: list[int]
    source_chain_id: int
    source_registry: str
    source_block_number: int
    source_block_hash: str
    registered_at_time: int
    adapter_id: str
    finality_delay_blocks: int
    output_dir: Path
    semantic_circuit_version: int = 1
    proof_file: Path | None = None
    public_signals_file: Path | None = None
    signatures_file: Path | None = None


@dataclass
class EvalBundleRequest:
    attestation_id: int
    benchmark_digest: str
    dataset_split_digest: str
    inference_config_digest: str
    randomness_seed_digest: str
    transcript_sample_count: int
    transcript_version: int
    threshold_bps: int
    evaluator: str
    evaluator_policy_digest: str
    evaluator_policy_version: int
    exact_score: int
    salt: int
    source_chain_id: int
    source_registry: str
    source_block_number: int
    source_block_hash: str
    claimed_at_block: int
    adapter_id: str
    finality_delay_blocks: int
    output_dir: Path
    eval_circuit_version: int = 1
    evaluator_signature: str = "0x"
    proof_file: Path | None = None
    public_signals_file: Path | None = None
    signatures_file: Path | None = None


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

    def prepare_attestation_bundle(self, request: AttestationBundleRequest) -> dict:
        request.output_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = request.output_dir / "attestation_manifest.json"
        semantic_input_path = request.output_dir / "semantic_input.json"
        package_path = request.output_dir / "attestation_package.json"

        job = self.submit_job("prepare_attestation_bundle", request.model_path, package_path)
        self.start_job(job.job_id)

        try:
            self._run_cli(
                "register-attestation",
                "--model",
                str(request.model_path),
                "--metadata",
                str(request.metadata_path),
                "--training",
                str(request.training_path),
                "--dataset",
                str(request.dataset_path),
                "--owner",
                request.owner,
                "--weights-root",
                str(request.weights_root),
                "--parent-attestation-id",
                str(request.parent_attestation_id),
                "--output",
                str(manifest_path),
            )
            self._run_cli(
                "build-semantic-input",
                "--manifest",
                str(manifest_path),
                "--attestation-id",
                str(request.attestation_id),
                "--registered-at-block",
                str(request.registered_at_block),
                "--path-elements",
                self._csv(request.path_elements),
                "--path-indices",
                self._csv(request.path_indices),
                "--output",
                str(semantic_input_path),
            )
            render_args = [
                "render-attestation-package",
                "--manifest",
                str(manifest_path),
                "--semantic-input",
                str(semantic_input_path),
                "--source-chain-id",
                str(request.source_chain_id),
                "--source-registry",
                request.source_registry,
                "--source-block-number",
                str(request.source_block_number),
                "--source-block-hash",
                request.source_block_hash,
                "--registered-at-time",
                str(request.registered_at_time),
                "--adapter-id",
                request.adapter_id,
                "--finality-delay-blocks",
                str(request.finality_delay_blocks),
                "--semantic-circuit-version",
                str(request.semantic_circuit_version),
                "--output",
                str(package_path),
            ]
            render_args.extend(self._optional_path_args("--proof-file", request.proof_file))
            render_args.extend(self._optional_path_args("--public-signals-file", request.public_signals_file))
            render_args.extend(self._optional_path_args("--signatures-file", request.signatures_file))
            self._run_cli(*render_args)
            self.complete_job(job.job_id)
            return {
                "job": self.get_job(job.job_id),
                "manifest_path": str(manifest_path),
                "semantic_input_path": str(semantic_input_path),
                "package_path": str(package_path),
            }
        except Exception as error:
            self.fail_job(job.job_id, str(error))
            raise

    def prepare_eval_bundle(self, request: EvalBundleRequest) -> dict:
        request.output_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = request.output_dir / "eval_claim_manifest.json"
        eval_input_path = request.output_dir / "eval_input.json"
        package_path = request.output_dir / "eval_package.json"

        job = self.submit_job("prepare_eval_bundle", request.output_dir, package_path)
        self.start_job(job.job_id)

        try:
            self._run_cli(
                "register-eval-claim",
                "--attestation-id",
                str(request.attestation_id),
                "--benchmark-digest",
                request.benchmark_digest,
                "--dataset-split-digest",
                request.dataset_split_digest,
                "--inference-config-digest",
                request.inference_config_digest,
                "--randomness-seed-digest",
                request.randomness_seed_digest,
                "--transcript-sample-count",
                str(request.transcript_sample_count),
                "--transcript-version",
                str(request.transcript_version),
                "--threshold-bps",
                str(request.threshold_bps),
                "--evaluator",
                request.evaluator,
                "--evaluator-policy-digest",
                request.evaluator_policy_digest,
                "--evaluator-policy-version",
                str(request.evaluator_policy_version),
                "--output",
                str(manifest_path),
            )
            self._run_cli(
                "build-eval-input",
                "--manifest",
                str(manifest_path),
                "--exact-score",
                str(request.exact_score),
                "--salt",
                str(request.salt),
                "--output",
                str(eval_input_path),
            )
            render_args = [
                "render-eval-package",
                "--manifest",
                str(manifest_path),
                "--eval-input",
                str(eval_input_path),
                "--source-chain-id",
                str(request.source_chain_id),
                "--source-registry",
                request.source_registry,
                "--source-block-number",
                str(request.source_block_number),
                "--source-block-hash",
                request.source_block_hash,
                "--claimed-at-block",
                str(request.claimed_at_block),
                "--adapter-id",
                request.adapter_id,
                "--finality-delay-blocks",
                str(request.finality_delay_blocks),
                "--eval-circuit-version",
                str(request.eval_circuit_version),
                "--evaluator-signature",
                request.evaluator_signature,
                "--output",
                str(package_path),
            ]
            render_args.extend(self._optional_path_args("--proof-file", request.proof_file))
            render_args.extend(self._optional_path_args("--public-signals-file", request.public_signals_file))
            render_args.extend(self._optional_path_args("--signatures-file", request.signatures_file))
            self._run_cli(*render_args)
            self.complete_job(job.job_id)
            return {
                "job": self.get_job(job.job_id),
                "manifest_path": str(manifest_path),
                "eval_input_path": str(eval_input_path),
                "package_path": str(package_path),
            }
        except Exception as error:
            self.fail_job(job.job_id, str(error))
            raise

    def _refresh_status(self) -> None:
        if self.status.queue_depth == 0 and self.status.proof_jobs_in_progress == 0:
            self.status.status = "idle"

    def _run_cli(self, *args: str) -> None:
        subprocess.run(
            [sys.executable, str(CLI_ENTRYPOINT), *args],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

    def _optional_path_args(self, flag: str, path: Path | None) -> list[str]:
        if path is None:
            return []
        return [flag, str(path)]

    def _csv(self, values: list[int]) -> str:
        return ",".join(str(value) for value in values)
