from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_ENTRYPOINT = REPO_ROOT / "cli" / "chain_attest" / "main.py"
FIXTURES = REPO_ROOT / "contracts" / "test" / "fixtures"
EVAL_WASM = REPO_ROOT / "circuits" / "eval_threshold_js" / "eval_threshold.wasm"
CONSTRAINT_CHECKS = REPO_ROOT / "circuits" / "scripts" / "check_eval_constraints.js"
EVALUATOR = "0x00000000000000000000000000000000000000bb"


class EvalPrivacyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="chainattest-eval-privacy-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir)

    def _cli(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(CLI_ENTRYPOINT), *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=check,
        )

    def _register_fixture_claim(self) -> Path:
        # The same private summary that produced contracts/test/fixtures/eval_input.json.
        manifest = self.temp_dir / "eval_claim_manifest.json"
        self._cli(
            "register-eval-claim",
            "--attestation-id", "42",
            "--benchmark-digest", "0x" + "11" * 32,
            "--dataset-split-digest", "0x" + "22" * 32,
            "--inference-config-digest", "0x" + "33" * 32,
            "--randomness-seed-digest", "0x" + "44" * 32,
            "--transcript-version", "2",
            "--batch-correct-counts", "20,24,23,25",
            "--batch-incorrect-counts", "2,1,3,2",
            "--batch-abstain-counts", "0,0,0,0",
            "--threshold-bps", "9200",
            "--min-sample-count", "50",
            "--evaluator", EVALUATOR,
            "--evaluator-policy-digest", "0x" + "66" * 32,
            "--output", str(manifest),
        )
        return manifest

    def _build_witness(self, manifest: Path, name: str, *blinding_args: str) -> dict:
        output = self.temp_dir / name
        self._cli("build-eval-input", "--manifest", str(manifest), "--output", str(output), *blinding_args)
        return json.loads(output.read_text())

    def test_cli_witness_matches_committed_circuit_fixture(self) -> None:
        fixture = json.loads((FIXTURES / "eval_input.json").read_text())
        manifest = self._register_fixture_claim()

        witness = self._build_witness(
            manifest,
            "eval_input.json",
            "--transcript-blinding", fixture["transcript_blinding"],
            "--score-blinding", fixture["score_blinding"],
        )

        self.assertEqual(witness, fixture)

    def test_fresh_blindings_make_identical_summaries_unlinkable(self) -> None:
        manifest = self._register_fixture_claim()

        first = self._build_witness(manifest, "first.json")
        second = self._build_witness(manifest, "second.json")

        self.assertEqual(first["verdict"], "1")
        self.assertEqual(second["verdict"], "1")
        self.assertNotEqual(first["transcript_blinding"], second["transcript_blinding"])
        self.assertNotEqual(first["score_blinding"], second["score_blinding"])
        self.assertNotEqual(first["transcript_commitment"], second["transcript_commitment"])
        self.assertNotEqual(first["score_commitment"], second["score_commitment"])
        # Blindings are full-width field elements, not small salts.
        self.assertGreater(int(first["score_blinding"]).bit_length(), 128)

    def test_score_opening_round_trip_and_rejects_a_false_opening(self) -> None:
        witness_path = self.temp_dir / "eval_input.json"
        witness_path.write_text((FIXTURES / "eval_input.json").read_text())
        package_path = self.temp_dir / "eval_package.json"
        public_signals = json.loads((FIXTURES / "eval_public.json").read_text())
        package_path.write_text(json.dumps({"scoreCommitment": public_signals[3]}) + "\n")

        opening_path = self.temp_dir / "score_opening.json"
        self._cli("export-score-opening", "--witness", str(witness_path), "--output", str(opening_path))
        opening = json.loads(opening_path.read_text())
        self.assertEqual(set(opening), {"correct_total", "sample_total", "score_blinding", "score_commitment"})

        verified = self._cli("verify-score-opening", "--package", str(package_path), "--opening", str(opening_path))
        self.assertIn("9200 bps", verified.stdout)

        opening["correct_total"] = str(int(opening["correct_total"]) + 1)
        forged_path = self.temp_dir / "forged_opening.json"
        forged_path.write_text(json.dumps(opening) + "\n")
        forged = self._cli(
            "verify-score-opening", "--package", str(package_path), "--opening", str(forged_path), check=False
        )
        self.assertNotEqual(forged.returncode, 0)

    def test_rejects_a_summary_below_the_minimum_sample_count(self) -> None:
        result = self._cli(
            "register-eval-claim",
            "--attestation-id", "42",
            "--benchmark-digest", "0x" + "11" * 32,
            "--dataset-split-digest", "0x" + "22" * 32,
            "--inference-config-digest", "0x" + "33" * 32,
            "--randomness-seed-digest", "0x" + "44" * 32,
            "--batch-correct-counts", "3",
            "--batch-incorrect-counts", "0",
            "--threshold-bps", "9200",
            "--min-sample-count", "50",
            "--evaluator", EVALUATOR,
            "--evaluator-policy-digest", "0x" + "66" * 32,
            "--output", str(self.temp_dir / "tiny.json"),
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)

    @unittest.skipUnless(EVAL_WASM.exists(), "eval circuit wasm not built or restored")
    def test_eval_circuit_rejects_malformed_witnesses(self) -> None:
        result = subprocess.run(
            ["node", str(CONSTRAINT_CHECKS)],
            cwd=REPO_ROOT / "circuits",
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertIn("eval constraint checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
