from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from typer.testing import CliRunner

from coordinator.chainattest_coordinator.ops import app
from coordinator.chainattest_coordinator.service import CoordinatorService


class OperatorCliTests(unittest.TestCase):
    committee_private_keys = [
        "0x1111111111111111111111111111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222222222222222222222222222",
    ]

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="chainattest-ops-"))
        self.db_path = self.temp_dir / "chainattest.db"
        self.state_path = self.temp_dir / "jobs.json"
        self.audit_log_path = self.temp_dir / "audit.jsonl"
        self.runner = CliRunner()
        self.service = CoordinatorService(
            state_path=self.state_path,
            audit_log_path=self.audit_log_path,
            db_path=self.db_path,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir)

    def _invoke(self, *args: str) -> object:
        result = self.runner.invoke(app, list(args))
        self.assertEqual(result.exit_code, 0, msg=result.stdout)
        return json.loads(result.stdout)

    def _write_attestation_package(self) -> Path:
        package_path = self.temp_dir / "attestation_package.json"
        package_path.write_text(
            json.dumps(
                {
                    "packageVersion": 1,
                    "packageType": 0,
                    "sourceChainId": "11155111",
                    "sourceSystemId": "0x" + "00" * 32,
                    "sourceChannelId": "0x" + "00" * 32,
                    "sourceTxId": "0x" + "00" * 32,
                    "sourceRegistry": "0x00000000000000000000000000000000000000aa",
                    "sourceBlockNumber": "54321",
                    "sourceBlockHash": "0x" + "55" * 32,
                    "attestationId": "42",
                    "modelFileDigest": "0x" + "11" * 32,
                    "weightsRoot": "12345",
                    "datasetCommitment": "0x" + "22" * 32,
                    "trainingCommitment": "0x" + "33" * 32,
                    "metadataDigest": "0x" + "44" * 32,
                    "owner": "0x00000000000000000000000000000000000000aa",
                    "parentAttestationId": "0",
                    "registeredAtBlock": "12345",
                    "registeredAtTime": "1775600000",
                    "attestationCommitment": "67890",
                    "adapterId": "0x" + "77" * 32,
                    "finalityDelayBlocks": "12",
                    "signatures": [],
                    "semanticCircuitVersion": 1,
                    "proof": {"pA": ["0", "0"], "pB": [["0", "0"], ["0", "0"]], "pC": ["0", "0"]},
                    "publicSignals": ["0", "0", "0", "0", "0"],
                },
                indent=2,
            )
            + "\n"
        )
        return package_path

    def _write_eval_package(self) -> Path:
        package_path = self.temp_dir / "eval_package.json"
        package_path.write_text(
            json.dumps(
                {
                    "packageVersion": 1,
                    "packageType": 2,
                    "sourceChainId": "11155111",
                    "sourceSystemId": "0x" + "00" * 32,
                    "sourceChannelId": "0x" + "00" * 32,
                    "sourceTxId": "0x" + "00" * 32,
                    "sourceRegistry": "0x00000000000000000000000000000000000000aa",
                    "sourceBlockNumber": "54322",
                    "sourceBlockHash": "0x" + "66" * 32,
                    "attestationId": "42",
                    "benchmarkDigest": "0x" + "11" * 32,
                    "evalTranscriptDigest": "0x" + "22" * 32,
                    "datasetSplitDigest": "0x" + "33" * 32,
                    "inferenceConfigDigest": "0x" + "44" * 32,
                    "randomnessSeedDigest": "0x" + "55" * 32,
                    "transcriptSampleCount": 100,
                    "transcriptVersion": 2,
                    "batchCount": 4,
                    "batchResultsDigest": "0x" + "66" * 32,
                    "correctCount": 92,
                    "incorrectCount": 8,
                    "abstainCount": 0,
                    "scoreCommitment": "123456",
                    "thresholdBps": 9200,
                    "evaluator": "0x00000000000000000000000000000000000000bb",
                    "evaluatorKeyId": "0x" + "77" * 32,
                    "evaluatorPolicyDigest": "0x" + "88" * 32,
                    "evaluatorPolicyVersion": 1,
                    "evaluatorSignature": "0x",
                    "claimedAtBlock": "54320",
                    "adapterId": "0x" + "77" * 32,
                    "finalityDelayBlocks": "12",
                    "signatures": [],
                    "evalCircuitVersion": 3,
                    "proof": {"pA": ["0", "0"], "pB": [["0", "0"], ["0", "0"]], "pC": ["0", "0"]},
                    "publicSignals": ["0", "0", "0", "0", "0", "0", "0"],
                },
                indent=2,
            )
            + "\n"
        )
        return package_path

    def test_list_jobs_and_show_job_report_persisted_state(self) -> None:
        input_path = self.temp_dir / "input.json"
        input_path.write_text("{}\n")

        job = self.service.submit_job("ops-check", input_path)
        self.service.start_job(job.job_id)

        listed = self._invoke(
            "list-jobs",
            "--db-path",
            str(self.db_path),
        )
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["job_id"], job.job_id)

        shown = self._invoke(
            "show-job",
            job.job_id,
            "--db-path",
            str(self.db_path),
        )
        self.assertEqual(shown["job_id"], job.job_id)
        self.assertEqual(shown["state"], "running")

    def test_tail_audit_returns_recent_records(self) -> None:
        input_path = self.temp_dir / "input.json"
        input_path.write_text("{}\n")

        job = self.service.submit_job("audit-check", input_path)
        self.service.start_job(job.job_id)
        self.service.complete_job(job.job_id)

        records = self._invoke(
            "tail-audit",
            "--db-path",
            str(self.db_path),
            "--limit",
            "2",
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(records[-1]["event_type"], "job_completed")

    def test_revoke_attestation_command_builds_signed_revoke_bundle(self) -> None:
        registered_package = self._write_attestation_package()
        output_dir = self.temp_dir / "attestation-revoke"

        result = self._invoke(
            "revoke-attestation",
            str(registered_package),
            "--source-tx-id",
            "0x" + "aa" * 32,
            "--source-block-number",
            "60001",
            "--source-block-hash",
            "0x" + "bb" * 32,
            "--output-dir",
            str(output_dir),
            "--destination-chain-id",
            "31337",
            "--committee-verifier-address",
            "0x00000000000000000000000000000000000000c1",
            "--committee-private-keys",
            ",".join(self.committee_private_keys),
            "--committee-threshold",
            "2",
            "--db-path",
            str(self.db_path),
        )

        package = json.loads(Path(result["bundle"]["package_path"]).read_text())
        self.assertEqual(package["packageType"], 1)
        self.assertEqual(package["sourceTxId"], "0x" + "aa" * 32)
        self.assertEqual(len(package["signatures"]), 2)

    def test_revoke_eval_command_builds_signed_revoke_bundle(self) -> None:
        registered_package = self._write_eval_package()
        output_dir = self.temp_dir / "eval-revoke"

        result = self._invoke(
            "revoke-eval",
            str(registered_package),
            "--source-tx-id",
            "0x" + "cc" * 32,
            "--source-block-number",
            "60002",
            "--source-block-hash",
            "0x" + "dd" * 32,
            "--output-dir",
            str(output_dir),
            "--destination-chain-id",
            "31337",
            "--committee-verifier-address",
            "0x00000000000000000000000000000000000000c2",
            "--committee-private-keys",
            ",".join(self.committee_private_keys),
            "--committee-threshold",
            "2",
            "--db-path",
            str(self.db_path),
        )

        package = json.loads(Path(result["bundle"]["package_path"]).read_text())
        self.assertEqual(package["packageType"], 3)
        self.assertEqual(package["sourceTxId"], "0x" + "cc" * 32)
        self.assertEqual(len(package["signatures"]), 2)


if __name__ == "__main__":
    unittest.main()
