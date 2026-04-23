from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from coordinator.chainattest_coordinator.service import (
    AttestationBundleRequest,
    CoordinatorService,
    EvalBundleRequest,
)


BN254_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_ENTRYPOINT = REPO_ROOT / "cli" / "chain_attest" / "crypto_bridge.js"


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


def wallet_address(private_key: str) -> str:
    result = subprocess.run(
        ["node", str(BRIDGE_ENTRYPOINT)],
        input=json.dumps({"action": "wallet_address", "privateKey": private_key}),
        text=True,
        capture_output=True,
        check=True,
        cwd=REPO_ROOT,
    )
    return json.loads(result.stdout)["address"]


class CoordinatorServiceTests(unittest.TestCase):
    committee_private_keys = [
        "0x1111111111111111111111111111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222222222222222222222222222",
    ]
    evaluator_private_key = "0x3333333333333333333333333333333333333333333333333333333333333333"

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="chainattest-coordinator-"))
        self.db_path = self.temp_dir / "chainattest.db"
        self.service = CoordinatorService(
            state_path=self.temp_dir / "jobs.json",
            audit_log_path=self.temp_dir / "audit.jsonl",
            db_path=self.db_path,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir)

    def test_prepare_attestation_bundle_generates_proof_and_signatures(self) -> None:
        model_path = self.temp_dir / "model.bin"
        metadata_path = self.temp_dir / "metadata.json"
        training_path = self.temp_dir / "training.json"
        dataset_path = self.temp_dir / "dataset.json"

        model_path.write_bytes(b"model-weights-v1")
        metadata_path.write_text('{"arch":"mlp"}\n')
        training_path.write_text('{"epochs":5}\n')
        dataset_path.write_text('{"split":"train"}\n')

        owner = "0x1234567890abcdef1234567890abcdef12345678"
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

        result = self.service.prepare_attestation_bundle(
            AttestationBundleRequest(
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
                source_registry="0x00000000000000000000000000000000000000aa",
                source_block_number=54321,
                source_block_hash="0x" + "55" * 32,
                registered_at_time=1775600000,
                adapter_id="0x" + "77" * 32,
                finality_delay_blocks=12,
                output_dir=self.temp_dir / "attestation",
                destination_chain_id=31337,
                committee_verifier_address="0x00000000000000000000000000000000000000b1",
                committee_private_keys=self.committee_private_keys,
                committee_threshold=2,
            )
        )

        package = json.loads(Path(result["package_path"]).read_text())
        self.assertEqual(package["packageType"], 0)
        self.assertEqual(len(package["signatures"]), 2)
        self.assertIn("pA", package["proof"])
        self.assertIn("pB", package["proof"])
        self.assertIn("pC", package["proof"])
        self.assertEqual(len(package["publicSignals"]), 5)
        self.assertTrue(Path(result["proof_path"]).exists())
        self.assertTrue(Path(result["signatures_path"]).exists())

    def test_prepare_eval_bundle_generates_proof_evaluator_signature_and_committee_signatures(self) -> None:
        evaluator = wallet_address(self.evaluator_private_key)

        result = self.service.prepare_eval_bundle(
            EvalBundleRequest(
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
                evaluator=evaluator,
                evaluator_policy_digest="0x" + "66" * 32,
                evaluator_policy_version=1,
                salt=123456,
                source_chain_id=11155111,
                source_registry="0x00000000000000000000000000000000000000aa",
                source_block_number=54322,
                source_block_hash="0x" + "88" * 32,
                claimed_at_block=54320,
                adapter_id="0x" + "77" * 32,
                finality_delay_blocks=12,
                output_dir=self.temp_dir / "eval",
                destination_chain_id=31337,
                committee_verifier_address="0x00000000000000000000000000000000000000b1",
                committee_private_keys=self.committee_private_keys,
                committee_threshold=2,
                eval_verifier_address="0x00000000000000000000000000000000000000c1",
                evaluator_private_key=self.evaluator_private_key,
            )
        )

        package = json.loads(Path(result["package_path"]).read_text())
        self.assertEqual(package["packageType"], 2)
        self.assertNotEqual(package["evaluatorSignature"], "0x")
        self.assertEqual(len(package["signatures"]), 2)
        self.assertIn("pA", package["proof"])
        self.assertIn("pB", package["proof"])
        self.assertIn("pC", package["proof"])
        self.assertEqual(len(package["publicSignals"]), 6)
        self.assertTrue(Path(result["proof_path"]).exists())
        self.assertTrue(Path(result["signatures_path"]).exists())

    def test_state_and_audit_persistence_do_not_leave_lock_files(self) -> None:
        input_path = self.temp_dir / "input.json"
        input_path.write_text("{}\n")

        job = self.service.submit_job("durability-check", input_path)
        self.service.start_job(job.job_id)
        self.service.complete_job(job.job_id)

        self.assertFalse((self.temp_dir / "jobs.json.lock").exists())
        self.assertFalse((self.temp_dir / "audit.jsonl.lock").exists())
        self.assertTrue(self.db_path.exists())

    def test_legacy_state_and_audit_are_migrated_into_sqlite(self) -> None:
        legacy_state_path = self.temp_dir / "legacy-jobs.json"
        legacy_audit_path = self.temp_dir / "legacy-audit.jsonl"
        legacy_db_path = self.temp_dir / "legacy.db"
        now = 1775600000

        legacy_state_path.write_text(
            json.dumps(
                {
                    "status": {
                        "status": "active",
                        "queue_depth": 1,
                        "pending_signature_requests": 0,
                        "proof_jobs_in_progress": 0,
                        "submitted_jobs": 0,
                        "completed_jobs": 0,
                        "failed_jobs": 0,
                    },
                    "job_order": ["job-legacy"],
                    "jobs": [
                        {
                            "job_id": "job-legacy",
                            "job_kind": "legacy-check",
                            "input_path": str(self.temp_dir / "legacy.json"),
                            "output_path": None,
                            "state": "queued",
                            "error": None,
                            "attempts": 0,
                            "tx_hash": None,
                            "metadata": {"correlation_id": "corr-legacy"},
                            "created_at": now,
                            "updated_at": now,
                        }
                    ],
                },
                indent=2,
            )
            + "\n"
        )
        legacy_audit_path.write_text(
            json.dumps(
                {
                    "timestamp": now,
                    "event_type": "job_submitted",
                    "job_id": "job-legacy",
                    "job_kind": "legacy-check",
                    "state": "queued",
                    "attempts": 0,
                    "tx_hash": None,
                    "metadata": {"correlation_id": "corr-legacy"},
                    "correlation_id": "corr-legacy",
                }
            )
            + "\n"
        )

        migrated = CoordinatorService(
            state_path=legacy_state_path,
            audit_log_path=legacy_audit_path,
            db_path=legacy_db_path,
        )

        self.assertEqual(len(migrated.list_jobs()), 1)
        self.assertEqual(migrated.list_jobs()[0]["job_id"], "job-legacy")
        self.assertEqual(migrated.tail_audit_events(limit=1)[0]["event_type"], "job_submitted")


if __name__ == "__main__":
    unittest.main()
