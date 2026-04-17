from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from committee.signer_service.signer import ApprovalRequest, CommitteeSigner, EvalAttestationRequest

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_ENTRYPOINT = REPO_ROOT / "cli" / "chain_attest" / "main.py"
CIRCUITS_ROOT = REPO_ROOT / "circuits"
SNARKJS_ENTRYPOINT = CIRCUITS_ROOT / "node_modules" / "snarkjs" / "build" / "cli.cjs"


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
    destination_chain_id: int | None = None
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
