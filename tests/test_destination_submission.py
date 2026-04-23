from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from urllib import request as urllib_request
from urllib import error as urllib_error

from coordinator.chainattest_coordinator.service import AttestationBundleRequest, CoordinatorService, EvalBundleRequest
from committee.signer_service.signer import HttpSignerClient


BN254_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_ENTRYPOINT = REPO_ROOT / "cli" / "chain_attest" / "crypto_bridge.js"
NPX_BIN = shutil.which("npx") or shutil.which("npx.cmd") or "npx"
DEPLOYER_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
COMMITTEE_PRIVATE_KEYS = [
    "0x59c6995e998f97a5a0044966f0945382db8a6d76a8c4b2f8e1d9f1c2b7b3a3a1",
    "0x5de4111afa1a4b94908df2b5af2d2aef62b88f7b64f7e01647e0c605b49d6e8b",
]
EVALUATOR_PRIVATE_KEY = "0x7c8521182946e51e65338c2f58b0b2f1b3e7b5f5e5d7e5c9f1d9a1c7e5b6f4e3"
ADAPTER_ID = "0x" + "77" * 32
SUBMITTER_ENV = "CHAINATTEST_TEST_SUBMITTER_KEY"
COMMITTEE_ENV_1 = "CHAINATTEST_TEST_COMMITTEE_KEY_1"
COMMITTEE_ENV_2 = "CHAINATTEST_TEST_COMMITTEE_KEY_2"
EVALUATOR_ENV = "CHAINATTEST_TEST_EVALUATOR_KEY"
AUTH_TOKEN_ENV = "CHAINATTEST_TEST_SIGNER_AUTH_TOKEN"
HOST_COMMAND = [sys.executable, str(REPO_ROOT / "committee" / "signer_service" / "host.py")]
HTTP_SERVICE_COMMAND = [sys.executable, str(REPO_ROOT / "committee" / "signer_service" / "http_service.py")]


def sha256_digest(path: Path) -> str:
    return "0x" + hashlib.sha256(path.read_bytes()).hexdigest()


def field_from_hex(hex_value: str) -> int:
    return int(hex_value, 16) % BN254_FIELD_MODULUS


def compute_semantic_root(
    model_digest: str,
    dataset_digest: str,
    training_digest: str,
    metadata_digest: str,
    owner: str,
    path_elements: list[int],
    path_indices: list[int],
) -> int:
    current = (
        field_from_hex(model_digest)
        + field_from_hex(dataset_digest) * 2
        + field_from_hex(training_digest) * 3
        + field_from_hex(metadata_digest) * 5
        + (int(owner, 16) % BN254_FIELD_MODULUS) * 7
    ) % BN254_FIELD_MODULUS
    for level, (element, index) in enumerate(zip(path_elements, path_indices), start=1):
        left = (current + (element - current) * index) % BN254_FIELD_MODULUS
        right = (element + (current - element) * index) % BN254_FIELD_MODULUS
        current = (left * 17 + right * 31 + level) % BN254_FIELD_MODULUS
    return current


def run_bridge(payload: dict) -> dict:
    result = subprocess.run(
        ["node", str(BRIDGE_ENTRYPOINT)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
        cwd=REPO_ROOT,
    )
    return json.loads(result.stdout)


def wallet_address(private_key: str) -> str:
    return run_bridge({"action": "wallet_address", "privateKey": private_key})["address"]


def allocate_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_rpc(rpc_url: str, timeout_seconds: float = 20.0) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() <= deadline:
        try:
            body = json.dumps(
                {"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1}
            ).encode()
            req = urllib_request.Request(
                rpc_url,
                data=body,
                headers={"Content-Type": "application/json"},
            )
            with urllib_request.urlopen(req, timeout=1.0) as response:
                payload = json.loads(response.read().decode())
                if "result" in payload:
                    return
        except Exception:
            time.sleep(0.25)
    raise TimeoutError(f"hardhat node did not start at {rpc_url}")


def wait_for_http_health(base_url: str, timeout_seconds: float = 20.0) -> None:
    deadline = time.time() + timeout_seconds
    while time.time() <= deadline:
        try:
            with urllib_request.urlopen(f"{base_url}/health", timeout=1.0) as response:
                payload = json.loads(response.read().decode())
                if payload.get("status") == "ok":
                    return
        except Exception:
            time.sleep(0.25)
    raise TimeoutError(f"http signer service did not start at {base_url}")


class DestinationSubmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rpc_port = allocate_port()
        cls.rpc_url = f"http://127.0.0.1:{cls.rpc_port}"
        cls.node_process = subprocess.Popen(
            [NPX_BIN, "hardhat", "node", "--hostname", "127.0.0.1", "--port", str(cls.rpc_port)],
            cwd=REPO_ROOT / "contracts",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_for_rpc(cls.rpc_url)

        cls.committee_addresses = [wallet_address(key) for key in COMMITTEE_PRIVATE_KEYS]
        cls.evaluator_address = wallet_address(EVALUATOR_PRIVATE_KEY)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.node_process.terminate()
        try:
            cls.node_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.node_process.kill()

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="chainattest-destination-"))
        self.db_path = self.temp_dir / "chainattest.db"
        self.state_path = self.temp_dir / "jobs.json"
        self.audit_log_path = self.temp_dir / "coordinator-audit.jsonl"
        self.signer_audit_log_path = self.temp_dir / "signer-audit.jsonl"
        self.http_signer_processes: list[subprocess.Popen] = []
        os.environ[SUBMITTER_ENV] = DEPLOYER_PRIVATE_KEY
        os.environ[COMMITTEE_ENV_1] = COMMITTEE_PRIVATE_KEYS[0]
        os.environ[COMMITTEE_ENV_2] = COMMITTEE_PRIVATE_KEYS[1]
        os.environ[EVALUATOR_ENV] = EVALUATOR_PRIVATE_KEY
        os.environ[AUTH_TOKEN_ENV] = "test-signer-token"
        os.environ["CHAINATTEST_SIGNER_AUTH_TOKEN"] = "test-signer-token"
        os.environ["CHAINATTEST_SIGNER_ALLOWED_ACTIONS"] = (
            "approve,sign_eval_attestation,submit_destination_package"
        )
        os.environ["CHAINATTEST_SIGNER_ALLOWED_PACKAGE_KINDS"] = "attestation,eval"
        os.environ["CHAINATTEST_SIGNER_ALLOWED_DESTINATION_CHAINS"] = "31337"
        os.environ["CHAINATTEST_SIGNER_AUDIT_LOG"] = str(self.signer_audit_log_path)
        self.service = CoordinatorService(
            state_path=self.state_path,
            audit_log_path=self.audit_log_path,
            db_path=self.db_path,
        )
        self.fixture = run_bridge(
            {
                "action": "deploy_destination_fixture",
                "rpcUrl": self.rpc_url,
                "privateKey": DEPLOYER_PRIVATE_KEY,
                "adapterId": ADAPTER_ID,
                "committeeThreshold": 2,
                "committeeSigners": self.committee_addresses,
                "authorizedEvaluators": [self.evaluator_address],
            }
        )

    def tearDown(self) -> None:
        for process in self.http_signer_processes:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        os.environ.pop(SUBMITTER_ENV, None)
        os.environ.pop(COMMITTEE_ENV_1, None)
        os.environ.pop(COMMITTEE_ENV_2, None)
        os.environ.pop(EVALUATOR_ENV, None)
        os.environ.pop(AUTH_TOKEN_ENV, None)
        os.environ.pop("CHAINATTEST_SIGNER_AUTH_TOKEN", None)
        os.environ.pop("CHAINATTEST_SIGNER_ALLOWED_ACTIONS", None)
        os.environ.pop("CHAINATTEST_SIGNER_ALLOWED_PACKAGE_KINDS", None)
        os.environ.pop("CHAINATTEST_SIGNER_ALLOWED_DESTINATION_CHAINS", None)
        os.environ.pop("CHAINATTEST_SIGNER_AUDIT_LOG", None)
        shutil.rmtree(self.temp_dir)

    def _read_audit_log(self, path: Path) -> list[dict]:
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def _start_http_signer(self, policy: dict) -> str:
        policy_path = self.temp_dir / f"signer-policy-{len(self.http_signer_processes)}.json"
        policy_path.write_text(json.dumps(policy, indent=2) + "\n")
        port = allocate_port()
        base_url = f"http://127.0.0.1:{port}"
        env = os.environ.copy()
        env["CHAINATTEST_SIGNER_HOST"] = "127.0.0.1"
        env["CHAINATTEST_SIGNER_PORT"] = str(port)
        env["CHAINATTEST_SIGNER_AUTH_TOKEN"] = os.environ[AUTH_TOKEN_ENV]
        env["CHAINATTEST_SIGNER_POLICY_PATH"] = str(policy_path)
        env["CHAINATTEST_SIGNER_AUDIT_LOG"] = str(self.signer_audit_log_path)
        process = subprocess.Popen(
            HTTP_SERVICE_COMMAND,
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        self.http_signer_processes.append(process)
        wait_for_http_health(base_url)
        return base_url

    def _policy(self) -> dict:
        submitter_address = wallet_address(DEPLOYER_PRIVATE_KEY)
        return {
            "allowed_actions": [
                "approve",
                "sign_eval_attestation",
                "submit_destination_package",
            ],
            "allowed_destination_chains": [str(self.fixture["chainId"])],
            "allowed_verifiers": [
                self.fixture["committeeAuthAdapter"],
                self.fixture["semanticVerifier"],
                self.fixture["evalThresholdVerifier"],
            ],
            "allowed_package_kinds": ["attestation", "eval"],
            "allowed_evaluators": [self.evaluator_address],
            "allowed_submitters": [submitter_address],
        }

    def _post_http_signer(
        self,
        base_url: str,
        route: str,
        payload: dict,
        *,
        token: str | None = None,
        timestamp: int | None = None,
        nonce: str | None = None,
    ) -> tuple[int, dict]:
        request = urllib_request.Request(
            f"{base_url}{route}",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token or os.environ[AUTH_TOKEN_ENV]}",
                "X-ChainAttest-Timestamp": str(timestamp or int(time.time())),
                "X-ChainAttest-Nonce": nonce or "nonce-http-test",
            },
            method="POST",
        )
        try:
            with urllib_request.urlopen(request, timeout=5.0) as response:
                return response.status, json.loads(response.read().decode())
        except urllib_error.HTTPError as error:
            return error.code, json.loads(error.read().decode())

    def _attestation_request(self) -> AttestationBundleRequest:
        model_path = self.temp_dir / "model.bin"
        metadata_path = self.temp_dir / "metadata.json"
        training_path = self.temp_dir / "training.json"
        dataset_path = self.temp_dir / "dataset.json"

        model_path.write_bytes(b"model-weights-v1")
        metadata_path.write_text('{"arch":"mlp"}\n')
        training_path.write_text('{"epochs":5}\n')
        dataset_path.write_text('{"split":"train"}\n')

        owner = wallet_address(DEPLOYER_PRIVATE_KEY)
        path_elements = [17, 23]
        path_indices = [0, 1]
        weights_root = compute_semantic_root(
            model_digest=sha256_digest(model_path),
            dataset_digest=sha256_digest(dataset_path),
            training_digest=sha256_digest(training_path),
            metadata_digest=sha256_digest(metadata_path),
            owner=owner,
            path_elements=path_elements,
            path_indices=path_indices,
        )

        return AttestationBundleRequest(
            model_path=model_path,
            metadata_path=metadata_path,
            training_path=training_path,
            dataset_path=dataset_path,
            owner=owner,
            weights_root=weights_root,
            parent_attestation_id=0,
            attestation_id=42,
            registered_at_block=12345,
            path_elements=path_elements,
            path_indices=path_indices,
            source_chain_id=11155111,
            source_registry=owner,
            source_block_number=54321,
            source_block_hash="0x" + "55" * 32,
            registered_at_time=1775600000,
            adapter_id=ADAPTER_ID,
            finality_delay_blocks=12,
            output_dir=self.temp_dir / "attestation",
            destination_chain_id=int(self.fixture["chainId"]),
            destination_rpc_url=self.rpc_url,
            destination_submitter_private_key=DEPLOYER_PRIVATE_KEY,
            destination_submitter_key_env=SUBMITTER_ENV,
            destination_verifier_address=self.fixture["semanticVerifier"],
            committee_verifier_address=self.fixture["committeeAuthAdapter"],
            committee_private_keys=COMMITTEE_PRIVATE_KEYS,
            committee_threshold=2,
        )

    def _eval_request(self) -> EvalBundleRequest:
        owner = wallet_address(DEPLOYER_PRIVATE_KEY)
        return EvalBundleRequest(
            attestation_id=42,
            benchmark_digest="0x" + "11" * 32,
            dataset_split_digest="0x" + "22" * 32,
            inference_config_digest="0x" + "33" * 32,
            randomness_seed_digest="0x" + "44" * 32,
            transcript_sample_count=100,
            transcript_version=2,
            correct_count=92,
            incorrect_count=8,
            abstain_count=0,
            threshold_bps=9200,
            evaluator=self.evaluator_address,
            evaluator_policy_digest="0x" + "66" * 32,
            evaluator_policy_version=1,
            salt=123456,
            source_chain_id=11155111,
            source_registry=owner,
            source_block_number=54322,
            source_block_hash="0x" + "88" * 32,
            claimed_at_block=54320,
            adapter_id=ADAPTER_ID,
            finality_delay_blocks=12,
            output_dir=self.temp_dir / "eval",
            destination_chain_id=int(self.fixture["chainId"]),
            destination_rpc_url=self.rpc_url,
            destination_submitter_private_key=DEPLOYER_PRIVATE_KEY,
            destination_submitter_key_env=SUBMITTER_ENV,
            destination_verifier_address=self.fixture["evalThresholdVerifier"],
            committee_verifier_address=self.fixture["committeeAuthAdapter"],
            committee_private_keys=COMMITTEE_PRIVATE_KEYS,
            committee_threshold=2,
            eval_verifier_address=self.fixture["evalThresholdVerifier"],
            evaluator_private_key=EVALUATOR_PRIVATE_KEY,
        )

    def test_orchestrates_attestation_submission_end_to_end(self) -> None:
        result = self.service.orchestrate_attestation(self._attestation_request())
        submission = result["submission"]
        self.assertIsNotNone(submission)
        self.assertEqual(submission["state"], "completed")
        self.assertIsNotNone(submission["tx_hash"])

        package = json.loads(Path(result["bundle"]["package_path"]).read_text())
        verification = run_bridge(
            {
                "action": "query_destination_verification",
                "rpcUrl": self.rpc_url,
                "packageKind": "attestation",
                "verifierAddress": self.fixture["semanticVerifier"],
                "package": package,
            }
        )
        self.assertTrue(verification["verified"])

    def test_orchestrates_eval_submission_end_to_end(self) -> None:
        attestation_result = self.service.orchestrate_attestation(self._attestation_request())
        self.assertEqual(attestation_result["submission"]["state"], "completed")

        eval_result = self.service.orchestrate_eval(self._eval_request())
        submission = eval_result["submission"]
        self.assertIsNotNone(submission)
        self.assertEqual(submission["state"], "completed")

        package = json.loads(Path(eval_result["bundle"]["package_path"]).read_text())
        verification = run_bridge(
            {
                "action": "query_destination_verification",
                "rpcUrl": self.rpc_url,
                "packageKind": "eval",
                "verifierAddress": self.fixture["evalThresholdVerifier"],
                "package": package,
            }
        )
        self.assertTrue(verification["verified"])

    def test_recovers_submitted_job_after_restart(self) -> None:
        result = self.service.orchestrate_attestation(self._attestation_request(), wait_for_receipt=False)
        submission = result["submission"]
        self.assertIsNotNone(submission)
        self.assertEqual(submission["state"], "submitted")

        restarted = CoordinatorService(state_path=self.state_path, db_path=self.db_path)
        resumed = restarted.resume_pending_jobs()
        self.assertEqual(len(resumed), 1)
        self.assertEqual(restarted.get_job(submission["job_id"])["state"], "completed")

    def test_persisted_state_uses_secret_refs_not_raw_private_keys(self) -> None:
        self.service.orchestrate_attestation(self._attestation_request(), wait_for_receipt=False)
        state_payload = json.loads(self.state_path.read_text())
        serialized = json.dumps(state_payload)

        self.assertNotIn(DEPLOYER_PRIVATE_KEY, serialized)
        self.assertIn(f"env:{SUBMITTER_ENV}", serialized)

    def test_retries_retryable_submission_failures_after_rpc_recovery(self) -> None:
        request = self._attestation_request()
        request.destination_rpc_url = "http://127.0.0.1:1"

        result = self.service.orchestrate_attestation(request)
        submission = result["submission"]
        self.assertIsNotNone(submission)
        self.assertEqual(submission["state"], "failed")
        self.assertEqual(submission["metadata"]["last_error_kind"], "transport_error")
        self.assertTrue(submission["metadata"]["retryable"])

        job_id = submission["job_id"]
        self.service.jobs[job_id].metadata["destination_rpc_url"] = self.rpc_url
        self.service.jobs[job_id].metadata["next_retry_at"] = 0
        self.service._persist_state()

        retried = self.service.retry_failed_jobs()
        self.assertEqual(len(retried), 1)
        self.assertEqual(self.service.get_job(job_id)["state"], "completed")

    def test_coordinator_audit_log_records_submission_lifecycle(self) -> None:
        result = self.service.orchestrate_attestation(self._attestation_request())
        submission = result["submission"]
        self.assertIsNotNone(submission)

        events = self._read_audit_log(self.audit_log_path)
        event_types = [event["event_type"] for event in events if event["job_id"] == submission["job_id"]]

        self.assertIn("job_submitted", event_types)
        self.assertIn("job_started", event_types)
        self.assertIn("job_prepared", event_types)
        self.assertIn("destination_submission_broadcast", event_types)
        self.assertIn("destination_receipt_observed", event_types)
        self.assertIn("job_completed", event_types)

    def test_external_signer_boundary_handles_committee_evaluator_and_submitter(self) -> None:
        attestation_request = self._attestation_request()
        attestation_request.destination_submitter_private_key = None
        attestation_request.destination_submitter_command = HOST_COMMAND
        attestation_request.destination_submitter_auth_token_env = AUTH_TOKEN_ENV
        attestation_request.committee_private_keys = []
        attestation_request.committee_key_envs = [COMMITTEE_ENV_1, COMMITTEE_ENV_2]
        attestation_request.committee_signer_command = HOST_COMMAND
        attestation_request.committee_signer_auth_token_env = AUTH_TOKEN_ENV

        attestation_result = self.service.orchestrate_attestation(attestation_request)
        self.assertEqual(attestation_result["submission"]["state"], "completed")

        eval_request = self._eval_request()
        eval_request.destination_submitter_private_key = None
        eval_request.destination_submitter_command = HOST_COMMAND
        eval_request.destination_submitter_auth_token_env = AUTH_TOKEN_ENV
        eval_request.committee_private_keys = []
        eval_request.committee_key_envs = [COMMITTEE_ENV_1, COMMITTEE_ENV_2]
        eval_request.committee_signer_command = HOST_COMMAND
        eval_request.committee_signer_auth_token_env = AUTH_TOKEN_ENV
        eval_request.evaluator_private_key = None
        eval_request.evaluator_key_env = EVALUATOR_ENV
        eval_request.evaluator_signer_command = HOST_COMMAND
        eval_request.evaluator_signer_auth_token_env = AUTH_TOKEN_ENV

        eval_result = self.service.orchestrate_eval(eval_request)
        self.assertEqual(eval_result["submission"]["state"], "completed")

        signer_events = self._read_audit_log(self.signer_audit_log_path)
        completed_actions = {
            event["action"]
            for event in signer_events
            if event["event_type"] == "signer_request_completed"
        }
        self.assertIn("approve", completed_actions)
        self.assertIn("sign_eval_attestation", completed_actions)
        self.assertIn("submit_destination_package", completed_actions)

    def test_http_signer_service_handles_committee_evaluator_and_submitter(self) -> None:
        service_url = self._start_http_signer(self._policy())

        attestation_request = self._attestation_request()
        attestation_request.destination_submitter_private_key = None
        attestation_request.destination_submitter_key_env = SUBMITTER_ENV
        attestation_request.signer_service_url = service_url
        attestation_request.signer_service_token_env = AUTH_TOKEN_ENV
        attestation_request.committee_private_keys = []
        attestation_request.committee_key_envs = [COMMITTEE_ENV_1, COMMITTEE_ENV_2]

        attestation_result = self.service.orchestrate_attestation(attestation_request)
        self.assertEqual(attestation_result["submission"]["state"], "completed")

        eval_request = self._eval_request()
        eval_request.destination_submitter_private_key = None
        eval_request.destination_submitter_key_env = SUBMITTER_ENV
        eval_request.signer_service_url = service_url
        eval_request.signer_service_token_env = AUTH_TOKEN_ENV
        eval_request.committee_private_keys = []
        eval_request.committee_key_envs = [COMMITTEE_ENV_1, COMMITTEE_ENV_2]
        eval_request.evaluator_private_key = None
        eval_request.evaluator_key_env = EVALUATOR_ENV

        eval_result = self.service.orchestrate_eval(eval_request)
        self.assertEqual(eval_result["submission"]["state"], "completed")

        signer_events = self._read_audit_log(self.signer_audit_log_path)
        completed_actions = {
            event["action"]
            for event in signer_events
            if event["event_type"] == "signer_http_request_completed"
        }
        self.assertIn("approve", completed_actions)
        self.assertIn("sign_eval_attestation", completed_actions)
        self.assertIn("submit_destination_package", completed_actions)

    def test_http_signer_service_rejects_bad_token(self) -> None:
        service_url = self._start_http_signer(self._policy())
        os.environ["CHAINATTEST_TEST_BAD_SIGNER_TOKEN"] = "wrong-token"
        self.addCleanup(lambda: os.environ.pop("CHAINATTEST_TEST_BAD_SIGNER_TOKEN", None))

        request = self._attestation_request()
        request.destination_submitter_private_key = None
        request.destination_submitter_key_env = SUBMITTER_ENV
        request.signer_service_url = service_url
        request.signer_service_token_env = "CHAINATTEST_TEST_BAD_SIGNER_TOKEN"
        request.committee_private_keys = []
        request.committee_key_envs = [COMMITTEE_ENV_1, COMMITTEE_ENV_2]

        with self.assertRaisesRegex(RuntimeError, "auth_failed"):
            self.service.prepare_attestation_bundle(request)

    def test_http_signer_service_rejects_replayed_nonce(self) -> None:
        service_url = self._start_http_signer(self._policy())

        request = self._attestation_request()
        request.destination_chain_id = None
        request.committee_verifier_address = None
        request.committee_private_keys = COMMITTEE_PRIVATE_KEYS
        bundle = self.service.prepare_attestation_bundle(request)
        package = json.loads(Path(bundle["package_path"]).read_text())
        payload = {
            "destinationChainId": int(self.fixture["chainId"]),
            "verifierAddress": self.fixture["committeeAuthAdapter"],
            "committeeKeyEnvs": [COMMITTEE_ENV_1, COMMITTEE_ENV_2],
            "threshold": 2,
            "package": package,
        }

        status, response = self._post_http_signer(
            service_url,
            "/approve",
            payload,
            nonce="replay-nonce",
        )
        self.assertEqual(status, 200)
        self.assertIn("signatures", response)

        replay_status, replay_response = self._post_http_signer(
            service_url,
            "/approve",
            payload,
            nonce="replay-nonce",
        )
        self.assertEqual(replay_status, 409)
        self.assertEqual(replay_response["error"]["code"], "replay_rejected")

    def test_external_signer_policy_rejects_disallowed_action(self) -> None:
        os.environ["CHAINATTEST_SIGNER_ALLOWED_ACTIONS"] = "approve,sign_eval_attestation"

        request = self._attestation_request()
        request.destination_submitter_private_key = None
        request.destination_submitter_command = HOST_COMMAND
        request.destination_submitter_auth_token_env = AUTH_TOKEN_ENV
        request.committee_private_keys = []
        request.committee_key_envs = [COMMITTEE_ENV_1, COMMITTEE_ENV_2]
        request.committee_signer_command = HOST_COMMAND
        request.committee_signer_auth_token_env = AUTH_TOKEN_ENV

        result = self.service.orchestrate_attestation(request)
        self.assertEqual(result["submission"]["state"], "failed")
        self.assertIn("policy rejected action", result["submission"]["error"].lower())

        signer_events = self._read_audit_log(self.signer_audit_log_path)
        rejected = [event for event in signer_events if event["event_type"] == "signer_request_rejected"]
        self.assertTrue(rejected)
        self.assertIn("policy rejected action", rejected[-1]["reason"].lower())


if __name__ == "__main__":
    unittest.main()
