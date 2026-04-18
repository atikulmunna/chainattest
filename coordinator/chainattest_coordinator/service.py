from dataclasses import asdict, dataclass, field
from enum import Enum
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4

from committee.signer_service.signer import ApprovalRequest, CommitteeSigner, EvalAttestationRequest

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_ENTRYPOINT = REPO_ROOT / "cli" / "chain_attest" / "main.py"
CIRCUITS_ROOT = REPO_ROOT / "circuits"
SNARKJS_ENTRYPOINT = CIRCUITS_ROOT / "node_modules" / "snarkjs" / "build" / "cli.cjs"


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PREPARED = "prepared"
    SUBMITTED = "submitted"
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
    attempts: int = 0
    tx_hash: str | None = None
    metadata: dict = field(default_factory=dict)
    created_at: int = 0
    updated_at: int = 0


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
    destination_chain_id: int | None = None
    destination_rpc_url: str | None = None
    destination_submitter_private_key: str | None = None
    destination_submitter_key_env: str | None = None
    destination_verifier_address: str | None = None
    committee_verifier_address: str | None = None
    committee_private_keys: list[str] = field(default_factory=list)
    committee_threshold: int | None = None
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
    destination_chain_id: int | None = None
    destination_rpc_url: str | None = None
    destination_submitter_private_key: str | None = None
    destination_submitter_key_env: str | None = None
    destination_verifier_address: str | None = None
    committee_verifier_address: str | None = None
    committee_private_keys: list[str] = field(default_factory=list)
    committee_threshold: int | None = None
    eval_verifier_address: str | None = None
    evaluator_private_key: str | None = None
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
    submitted_jobs: int = 0
    completed_jobs: int = 0
    failed_jobs: int = 0


@dataclass
class SubmissionRequest:
    package_path: Path
    package_kind: str
    destination_rpc_url: str
    destination_verifier_address: str
    destination_submitter_private_key: str | None = None
    destination_submitter_secret_ref: str | None = None
    wait_for_receipt: bool = True
    receipt_timeout_seconds: float = 30.0
    poll_interval_seconds: float = 1.0
    max_attempts: int = 3
    retry_backoff_seconds: float = 2.0
    retry_backoff_multiplier: float = 2.0


class CoordinatorService:
    def __init__(self, state_path: Path | None = None) -> None:
        self.state_path = state_path or (REPO_ROOT / "coordinator" / "state" / "jobs.json")
        self.status = CoordinatorStatus()
        self.jobs: dict[str, CoordinatorJob] = {}
        self.job_order: list[str] = []
        self.runtime_secrets: dict[str, str] = {}
        self._load_state()

    def health(self) -> dict:
        return asdict(self.status)

    def submit_job(self, job_kind: str, input_path: Path, output_path: Path | None = None) -> CoordinatorJob:
        now = int(time.time())
        job = CoordinatorJob(
            job_id=f"job-{uuid4()}",
            job_kind=job_kind,
            input_path=str(input_path),
            output_path=str(output_path) if output_path else None,
            created_at=now,
            updated_at=now,
        )
        self.jobs[job.job_id] = job
        self.job_order.append(job.job_id)
        self.status.queue_depth += 1
        if self.status.status == "idle":
            self.status.status = "active"
        self._persist_state()
        return job

    def start_job(self, job_id: str) -> CoordinatorJob:
        job = self.jobs[job_id]
        if job.state == JobState.QUEUED:
            self.status.queue_depth -= 1
            self.status.proof_jobs_in_progress += 1
        job.state = JobState.RUNNING
        job.updated_at = int(time.time())
        self._persist_state()
        return job

    def complete_job(self, job_id: str) -> CoordinatorJob:
        job = self.jobs[job_id]
        if job.state == JobState.RUNNING:
            self.status.proof_jobs_in_progress -= 1
        elif job.state == JobState.SUBMITTED:
            self.status.submitted_jobs -= 1
        job.state = JobState.COMPLETED
        job.updated_at = int(time.time())
        self.status.completed_jobs += 1
        self._refresh_status()
        self._persist_state()
        return job

    def fail_job(self, job_id: str, error: str) -> CoordinatorJob:
        job = self.jobs[job_id]
        if job.state == JobState.RUNNING:
            self.status.proof_jobs_in_progress -= 1
        elif job.state == JobState.SUBMITTED:
            self.status.submitted_jobs -= 1
        elif job.state == JobState.QUEUED:
            self.status.queue_depth -= 1
        job.state = JobState.FAILED
        job.error = error
        job.updated_at = int(time.time())
        self.status.failed_jobs += 1
        self._refresh_status()
        self._persist_state()
        return job

    def get_job(self, job_id: str) -> dict:
        return asdict(self.jobs[job_id])

    def list_jobs(self) -> list[dict]:
        return [asdict(self.jobs[job_id]) for job_id in self.job_order]

    def orchestrate_attestation(
        self,
        request: AttestationBundleRequest,
        wait_for_receipt: bool = True,
        receipt_timeout_seconds: float = 30.0,
        poll_interval_seconds: float = 1.0,
    ) -> dict:
        bundle = self.prepare_attestation_bundle(request)
        submission = None
        if self._can_submit_destination(
            request.destination_rpc_url,
            request.destination_submitter_private_key,
            request.destination_submitter_key_env,
            request.destination_verifier_address,
        ):
            submitter_secret_ref = self._register_secret_ref(
                job_key=str(bundle["job"]["job_id"]),
                secret=request.destination_submitter_private_key,
                env_name=request.destination_submitter_key_env,
                purpose="destination_submitter",
            )
            submission = self.submit_package(
                SubmissionRequest(
                    package_path=Path(bundle["package_path"]),
                    package_kind="attestation",
                    destination_rpc_url=request.destination_rpc_url,
                    destination_verifier_address=request.destination_verifier_address,
                    destination_submitter_secret_ref=submitter_secret_ref,
                    wait_for_receipt=wait_for_receipt,
                    receipt_timeout_seconds=receipt_timeout_seconds,
                    poll_interval_seconds=poll_interval_seconds,
                )
            )
        return {
            "bundle": bundle,
            "submission": submission,
        }

    def orchestrate_eval(
        self,
        request: EvalBundleRequest,
        wait_for_receipt: bool = True,
        receipt_timeout_seconds: float = 30.0,
        poll_interval_seconds: float = 1.0,
    ) -> dict:
        bundle = self.prepare_eval_bundle(request)
        submission = None
        if self._can_submit_destination(
            request.destination_rpc_url,
            request.destination_submitter_private_key,
            request.destination_submitter_key_env,
            request.destination_verifier_address,
        ):
            submitter_secret_ref = self._register_secret_ref(
                job_key=str(bundle["job"]["job_id"]),
                secret=request.destination_submitter_private_key,
                env_name=request.destination_submitter_key_env,
                purpose="destination_submitter",
            )
            submission = self.submit_package(
                SubmissionRequest(
                    package_path=Path(bundle["package_path"]),
                    package_kind="eval",
                    destination_rpc_url=request.destination_rpc_url,
                    destination_verifier_address=request.destination_verifier_address,
                    destination_submitter_secret_ref=submitter_secret_ref,
                    wait_for_receipt=wait_for_receipt,
                    receipt_timeout_seconds=receipt_timeout_seconds,
                    poll_interval_seconds=poll_interval_seconds,
                )
            )
        return {
            "bundle": bundle,
            "submission": submission,
        }

    def submit_package(self, request: SubmissionRequest, job_id: str | None = None) -> dict:
        job = self.jobs[job_id] if job_id is not None else self.submit_job(
            f"submit_{request.package_kind}_package",
            request.package_path,
            request.package_path,
        )
        if job.state == JobState.QUEUED:
            self.start_job(job.job_id)

        try:
            package_payload = self._load_json(request.package_path)
            self._mark_prepared(
                job.job_id,
                {
                    "package_path": str(request.package_path),
                    "package_kind": request.package_kind,
                    "destination_rpc_url": request.destination_rpc_url,
                    "destination_verifier_address": request.destination_verifier_address,
                    "destination_submitter_secret_ref": request.destination_submitter_secret_ref
                    or self._register_secret_ref(
                        job_key=job.job_id,
                        secret=request.destination_submitter_private_key,
                        env_name=None,
                        purpose="destination_submitter",
                    ),
                    "wait_for_receipt": request.wait_for_receipt,
                    "receipt_timeout_seconds": request.receipt_timeout_seconds,
                    "poll_interval_seconds": request.poll_interval_seconds,
                    "max_attempts": request.max_attempts,
                    "retry_backoff_seconds": request.retry_backoff_seconds,
                    "retry_backoff_multiplier": request.retry_backoff_multiplier,
                },
            )
            self._submit_prepared_job(job.job_id, package_payload)
            if request.wait_for_receipt:
                self._wait_for_job_receipt(
                    job.job_id,
                    timeout_seconds=request.receipt_timeout_seconds,
                    poll_interval_seconds=request.poll_interval_seconds,
                )
            return self.get_job(job.job_id)
        except Exception as error:
            if self._schedule_retry_if_retryable(job.job_id, error):
                return self.get_job(job.job_id)
            self.fail_job(job.job_id, str(error))
            return self.get_job(job.job_id)

    def resume_pending_jobs(self) -> list[dict]:
        resumed: list[dict] = []
        for job_id in list(self.job_order):
            job = self.jobs[job_id]
            if job.state == JobState.PREPARED:
                try:
                    package_payload = self._load_json(Path(job.metadata["package_path"]))
                    self._submit_prepared_job(job_id, package_payload)
                    if job.metadata.get("wait_for_receipt", True):
                        self._wait_for_job_receipt(
                            job_id,
                            timeout_seconds=float(job.metadata.get("receipt_timeout_seconds", 30.0)),
                            poll_interval_seconds=float(job.metadata.get("poll_interval_seconds", 1.0)),
                        )
                except Exception as error:
                    self.fail_job(job_id, str(error))
                resumed.append(self.get_job(job_id))
            elif job.state == JobState.SUBMITTED:
                receipt = self._fetch_receipt(job.tx_hash, job.metadata["destination_rpc_url"])
                if receipt is not None:
                    if int(receipt["status"]) == 1:
                        job.metadata["receipt"] = receipt
                        self.complete_job(job_id)
                    else:
                        self.fail_job(job_id, f"destination transaction failed: {job.tx_hash}")
                    resumed.append(self.get_job(job_id))
            elif job.state == JobState.FAILED and self._is_retry_due(job):
                try:
                    package_payload = self._load_json(Path(job.metadata["package_path"]))
                    self._mark_prepared(job_id, job.metadata)
                    self._submit_prepared_job(job_id, package_payload)
                    if job.metadata.get("wait_for_receipt", True):
                        self._wait_for_job_receipt(
                            job_id,
                            timeout_seconds=float(job.metadata.get("receipt_timeout_seconds", 30.0)),
                            poll_interval_seconds=float(job.metadata.get("poll_interval_seconds", 1.0)),
                        )
                except Exception as error:
                    if not self._schedule_retry_if_retryable(job_id, error):
                        self.fail_job(job_id, str(error))
                resumed.append(self.get_job(job_id))
        return resumed

    def retry_failed_jobs(self) -> list[dict]:
        return self.resume_pending_jobs()

    def prepare_attestation_bundle(self, request: AttestationBundleRequest) -> dict:
        request.output_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = request.output_dir / "attestation_manifest.json"
        semantic_input_path = request.output_dir / "semantic_input.json"
        proof_path = request.proof_file or request.output_dir / "semantic_proof.json"
        public_signals_path = request.public_signals_file or request.output_dir / "semantic_public.json"
        signatures_path = request.signatures_file or request.output_dir / "committee_signatures.json"
        package_path = request.output_dir / "attestation_package.json"

        job = self.submit_job("prepare_attestation_bundle", request.model_path, package_path)
        self.start_job(job.job_id)

        try:
            self._run_cli(
                "register-attestation",
                str(request.model_path),
                str(request.metadata_path),
                str(request.training_path),
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
            if request.proof_file is None or request.public_signals_file is None:
                self._generate_proof(
                    circuit_name="semantic_attestation",
                    input_path=semantic_input_path,
                    proof_path=proof_path,
                    public_signals_path=public_signals_path,
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
            render_args.extend(self._optional_path_args("--proof-file", proof_path))
            render_args.extend(self._optional_path_args("--public-signals-file", public_signals_path))
            self._run_cli(*render_args)
            if request.signatures_file is None:
                signatures_output = self._collect_committee_signatures(
                    package_path=package_path,
                    output_path=signatures_path,
                    destination_chain_id=request.destination_chain_id,
                    verifier_address=request.committee_verifier_address,
                    private_keys=request.committee_private_keys,
                    threshold=request.committee_threshold,
                )
            else:
                signatures_output = request.signatures_file

            if signatures_output is not None:
                render_args.extend(["--signatures-file", str(signatures_output)])
                self._run_cli(*render_args)
            self.complete_job(job.job_id)
            return {
                "job": self.get_job(job.job_id),
                "manifest_path": str(manifest_path),
                "semantic_input_path": str(semantic_input_path),
                "proof_path": str(proof_path),
                "public_signals_path": str(public_signals_path),
                "signatures_path": str(signatures_output) if signatures_output else None,
                "package_path": str(package_path),
            }
        except Exception as error:
            self.fail_job(job.job_id, str(error))
            raise

    def prepare_eval_bundle(self, request: EvalBundleRequest) -> dict:
        request.output_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = request.output_dir / "eval_claim_manifest.json"
        eval_input_path = request.output_dir / "eval_input.json"
        proof_path = request.proof_file or request.output_dir / "eval_proof.json"
        public_signals_path = request.public_signals_file or request.output_dir / "eval_public.json"
        signatures_path = request.signatures_file or request.output_dir / "committee_signatures.json"
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
            if request.proof_file is None or request.public_signals_file is None:
                self._generate_proof(
                    circuit_name="eval_threshold",
                    input_path=eval_input_path,
                    proof_path=proof_path,
                    public_signals_path=public_signals_path,
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
            render_args.extend(self._optional_path_args("--proof-file", proof_path))
            render_args.extend(self._optional_path_args("--public-signals-file", public_signals_path))
            self._run_cli(*render_args)

            evaluator_signature = self._sign_eval_attestation(
                package_path=package_path,
                destination_chain_id=request.destination_chain_id,
                verifier_address=request.eval_verifier_address,
                private_key=request.evaluator_private_key,
                existing_signature=request.evaluator_signature,
            )
            if request.signatures_file is None:
                signatures_output = self._collect_committee_signatures(
                    package_path=package_path,
                    output_path=signatures_path,
                    destination_chain_id=request.destination_chain_id,
                    verifier_address=request.committee_verifier_address,
                    private_keys=request.committee_private_keys,
                    threshold=request.committee_threshold,
                )
            else:
                signatures_output = request.signatures_file

            rerender_args = [
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
                evaluator_signature,
                "--output",
                str(package_path),
            ]
            rerender_args.extend(self._optional_path_args("--proof-file", proof_path))
            rerender_args.extend(self._optional_path_args("--public-signals-file", public_signals_path))
            rerender_args.extend(self._optional_path_args("--signatures-file", signatures_output))
            self._run_cli(*rerender_args)
            self.complete_job(job.job_id)
            return {
                "job": self.get_job(job.job_id),
                "manifest_path": str(manifest_path),
                "eval_input_path": str(eval_input_path),
                "proof_path": str(proof_path),
                "public_signals_path": str(public_signals_path),
                "signatures_path": str(signatures_output) if signatures_output else None,
                "package_path": str(package_path),
            }
        except Exception as error:
            self.fail_job(job.job_id, str(error))
            raise

    def _refresh_status(self) -> None:
        if (
            self.status.queue_depth == 0
            and self.status.proof_jobs_in_progress == 0
            and self.status.submitted_jobs == 0
        ):
            self.status.status = "idle"
        else:
            self.status.status = "active"

    def _run_cli(self, *args: str) -> None:
        subprocess.run(
            [sys.executable, str(CLI_ENTRYPOINT), *args],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

    def _run_bridge(self, payload: dict) -> dict:
        result = subprocess.run(
            ["node", str(REPO_ROOT / "cli" / "chain_attest" / "crypto_bridge.js")],
            input=json.dumps(payload),
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    def _optional_path_args(self, flag: str, path: Path | None) -> list[str]:
        if path is None:
            return []
        return [flag, str(path)]

    def _csv(self, values: list[int]) -> str:
        return ",".join(str(value) for value in values)

    def _mark_prepared(self, job_id: str, metadata: dict) -> CoordinatorJob:
        job = self.jobs[job_id]
        if job.state == JobState.RUNNING:
            self.status.proof_jobs_in_progress -= 1
        job.state = JobState.PREPARED
        job.metadata = metadata
        job.updated_at = int(time.time())
        self._refresh_status()
        self._persist_state()
        return job

    def _submit_prepared_job(self, job_id: str, package_payload: dict) -> CoordinatorJob:
        job = self.jobs[job_id]
        if job.state == JobState.RUNNING:
            self.status.proof_jobs_in_progress -= 1
        if job.state != JobState.SUBMITTED:
            self.status.submitted_jobs += 1
        job.attempts += 1
        submitter_private_key = self._resolve_secret_ref(job.metadata["destination_submitter_secret_ref"])
        response = self._run_bridge(
            {
                "action": "submit_destination_package",
                "rpcUrl": job.metadata["destination_rpc_url"],
                "privateKey": submitter_private_key,
                "verifierAddress": job.metadata["destination_verifier_address"],
                "packageKind": job.metadata["package_kind"],
                "package": package_payload,
            }
        )
        job.state = JobState.SUBMITTED
        job.tx_hash = response["txHash"]
        job.error = None
        job.metadata.pop("last_error_kind", None)
        job.metadata.pop("retryable", None)
        job.metadata.pop("next_retry_at", None)
        job.updated_at = int(time.time())
        self._refresh_status()
        self._persist_state()
        return job

    def _wait_for_job_receipt(
        self,
        job_id: str,
        timeout_seconds: float = 30.0,
        poll_interval_seconds: float = 1.0,
    ) -> CoordinatorJob:
        deadline = time.time() + timeout_seconds
        while time.time() <= deadline:
            job = self.jobs[job_id]
            receipt = self._fetch_receipt(job.tx_hash, job.metadata["destination_rpc_url"])
            job.metadata["last_receipt_check_at"] = int(time.time())
            if receipt is not None:
                job.metadata["receipt"] = receipt
                if int(receipt["status"]) == 1:
                    self.complete_job(job_id)
                else:
                    self.fail_job(job_id, f"destination transaction failed: {job.tx_hash}")
                return self.jobs[job_id]
            time.sleep(poll_interval_seconds)
        self._persist_state()
        return self.jobs[job_id]

    def _fetch_receipt(self, tx_hash: str | None, rpc_url: str) -> dict | None:
        if tx_hash is None:
            return None
        response = self._run_bridge(
            {
                "action": "get_transaction_receipt",
                "rpcUrl": rpc_url,
                "txHash": tx_hash,
            }
        )
        return response["receipt"]

    def _can_submit_destination(
        self,
        rpc_url: str | None,
        submitter_private_key: str | None,
        submitter_key_env: str | None,
        verifier_address: str | None,
    ) -> bool:
        return (
            rpc_url is not None
            and verifier_address is not None
            and (submitter_private_key is not None or submitter_key_env is not None)
        )

    def _generate_proof(
        self,
        circuit_name: str,
        input_path: Path,
        proof_path: Path,
        public_signals_path: Path,
    ) -> None:
        proof_path.parent.mkdir(parents=True, exist_ok=True)
        public_signals_path.parent.mkdir(parents=True, exist_ok=True)
        wasm_path, zkey_path = self._proof_artifacts(circuit_name)
        subprocess.run(
            [
                "node",
                str(SNARKJS_ENTRYPOINT),
                "groth16",
                "fullprove",
                str(input_path),
                str(wasm_path),
                str(zkey_path),
                str(proof_path),
                str(public_signals_path),
            ],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

    def _proof_artifacts(self, circuit_name: str) -> tuple[Path, Path]:
        if circuit_name == "semantic_attestation":
            return (
                CIRCUITS_ROOT / "semantic_attestation_js" / "semantic_attestation.wasm",
                CIRCUITS_ROOT / "semantic_attestation_final.zkey",
            )
        if circuit_name == "eval_threshold":
            return (
                CIRCUITS_ROOT / "eval_threshold_js" / "eval_threshold.wasm",
                CIRCUITS_ROOT / "eval_threshold_final.zkey",
            )
        raise ValueError(f"unsupported circuit name: {circuit_name}")

    def _collect_committee_signatures(
        self,
        package_path: Path,
        output_path: Path,
        destination_chain_id: int | None,
        verifier_address: str | None,
        private_keys: list[str],
        threshold: int | None,
    ) -> Path | None:
        if destination_chain_id is None or verifier_address is None or not private_keys:
            return None

        package_payload = self._load_json(package_path)
        signer = CommitteeSigner(private_keys)
        self.status.pending_signature_requests += 1
        try:
            response = signer.approve(
                ApprovalRequest(
                    package=package_payload,
                    destination_chain_id=destination_chain_id,
                    verifier_address=verifier_address,
                    threshold=threshold,
                )
            )
        finally:
            self.status.pending_signature_requests -= 1

        self._dump_json(output_path, response["signatures"])
        return output_path

    def _sign_eval_attestation(
        self,
        package_path: Path,
        destination_chain_id: int | None,
        verifier_address: str | None,
        private_key: str | None,
        existing_signature: str,
    ) -> str:
        if existing_signature != "0x":
            return existing_signature
        if destination_chain_id is None or verifier_address is None or private_key is None:
            return existing_signature

        package_payload = self._load_json(package_path)
        signer = CommitteeSigner([])
        signed = signer.sign_eval_attestation(
            EvalAttestationRequest(
                package=package_payload,
                destination_chain_id=destination_chain_id,
                verifier_address=verifier_address,
                private_key=private_key,
            )
        )
        if signed["signerAddress"].lower() != package_payload["evaluator"].lower():
            raise ValueError("evaluator private key does not match package evaluator address")
        if signed["evaluatorKeyId"].lower() != package_payload["evaluatorKeyId"].lower():
            raise ValueError("evaluator private key does not match package evaluator key id")
        return signed["evaluatorSignature"]

    def _load_json(self, path: Path) -> dict | list:
        return json.loads(path.read_text())

    def _dump_json(self, path: Path, payload: dict | list) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n")

    def _register_secret_ref(
        self,
        job_key: str,
        secret: str | None,
        env_name: str | None,
        purpose: str,
    ) -> str:
        if env_name is not None:
            return f"env:{env_name}"
        if secret is None:
            raise ValueError(f"{purpose} secret is required")
        ref = f"memory:{job_key}:{purpose}"
        self.runtime_secrets[ref] = secret
        return ref

    def _resolve_secret_ref(self, secret_ref: str) -> str:
        if secret_ref.startswith("env:"):
            env_name = secret_ref.split(":", 1)[1]
            value = os.environ.get(env_name)
            if value is None:
                raise ValueError(f"required secret environment variable is missing: {env_name}")
            return value
        if secret_ref.startswith("memory:"):
            value = self.runtime_secrets.get(secret_ref)
            if value is None:
                raise ValueError(
                    "required runtime secret is unavailable after restart; use an environment-backed secret ref"
                )
            return value
        raise ValueError(f"unsupported secret ref: {secret_ref}")

    def _schedule_retry_if_retryable(self, job_id: str, error: Exception) -> bool:
        job = self.jobs[job_id]
        error_kind, retryable = self._classify_submission_error(error)
        max_attempts = int(job.metadata.get("max_attempts", 3))
        if not retryable or job.attempts >= max_attempts:
            return False

        base = float(job.metadata.get("retry_backoff_seconds", 2.0))
        multiplier = float(job.metadata.get("retry_backoff_multiplier", 2.0))
        delay = base * (multiplier ** max(job.attempts - 1, 0))
        self._schedule_retry(job_id, str(error), error_kind, delay)
        return True

    def _schedule_retry(self, job_id: str, error: str, error_kind: str, delay_seconds: float) -> CoordinatorJob:
        job = self.jobs[job_id]
        if job.state == JobState.RUNNING:
            self.status.proof_jobs_in_progress -= 1
        elif job.state == JobState.SUBMITTED:
            self.status.submitted_jobs -= 1
        job.state = JobState.FAILED
        job.error = error
        job.metadata["last_error_kind"] = error_kind
        job.metadata["retryable"] = True
        job.metadata["next_retry_at"] = time.time() + delay_seconds
        job.updated_at = int(time.time())
        self.status.failed_jobs += 1
        self._refresh_status()
        self._persist_state()
        return job

    def _classify_submission_error(self, error: Exception) -> tuple[str, bool]:
        message = str(error).lower()
        stderr = ""
        if isinstance(error, subprocess.CalledProcessError):
            stderr = (error.stderr or "").lower()
            message = f"{message} {stderr}"

        if "required secret environment variable" in message or "runtime secret is unavailable" in message:
            return ("secret_unavailable", False)
        if "execution reverted" in message or "invalidproof" in message or "replaydetected" in message:
            return ("contract_revert", False)
        if "unsupported secret ref" in message or "unsupported package kind" in message:
            return ("configuration_error", False)
        if any(
            token in message
            for token in [
                "econnrefused",
                "network",
                "socket",
                "timeout",
                "missing response",
                "connect",
                "connection",
                "server error",
                "temporarily unavailable",
            ]
        ):
            return ("transport_error", True)
        if isinstance(error, subprocess.CalledProcessError):
            return ("bridge_error", True)
        return ("submission_error", False)

    def _is_retry_due(self, job: CoordinatorJob) -> bool:
        if not job.metadata.get("retryable", False):
            return False
        next_retry_at = float(job.metadata.get("next_retry_at", 0))
        return time.time() >= next_retry_at

    def _load_state(self) -> None:
        if not self.state_path.exists():
            return

        payload = json.loads(self.state_path.read_text())
        status_payload = payload.get("status")
        if status_payload is not None:
            self.status = CoordinatorStatus(**status_payload)

        self.job_order = payload.get("job_order", [])
        for raw_job in payload.get("jobs", []):
            raw_job["state"] = JobState(raw_job["state"])
            job = CoordinatorJob(**raw_job)
            self.jobs[job.job_id] = job

        self._refresh_status()

    def _persist_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "status": asdict(self.status),
            "job_order": self.job_order,
            "jobs": [asdict(self.jobs[job_id]) for job_id in self.job_order],
        }
        self.state_path.write_text(json.dumps(payload, indent=2) + "\n")
