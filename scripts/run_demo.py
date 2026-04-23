from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from urllib import request as urllib_request

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from coordinator.chainattest_coordinator.service import (  # noqa: E402
    AttestationBundleRequest,
    CoordinatorService,
    EvalBundleRequest,
    SubmissionRequest,
)


BRIDGE_ENTRYPOINT = REPO_ROOT / "cli" / "chain_attest" / "crypto_bridge.js"
NPX_BIN = shutil.which("npx") or shutil.which("npx.cmd") or "npx"

DEPLOYER_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
COMMITTEE_PRIVATE_KEYS = [
    "0x59c6995e998f97a5a0044966f0945382db8a6d76a8c4b2f8e1d9f1c2b7b3a3a1",
    "0x5de4111afa1a4b94908df2b5af2d2aef62b88f7b64f7e01647e0c605b49d6e8b",
]
EVALUATOR_PRIVATE_KEY = "0x7c8521182946e51e65338c2f58b0b2f1b3e7b5f5e5d7e5c9f1d9a1c7e5b6f4e3"
SUBMITTER_ENV = "CHAINATTEST_DEMO_SUBMITTER_KEY"
COMMITTEE_ENV_1 = "CHAINATTEST_DEMO_COMMITTEE_KEY_1"
COMMITTEE_ENV_2 = "CHAINATTEST_DEMO_COMMITTEE_KEY_2"
EVALUATOR_ENV = "CHAINATTEST_DEMO_EVALUATOR_KEY"
AUTH_TOKEN_ENV = "CHAINATTEST_DEMO_SIGNER_TOKEN"
ADAPTER_ID = "0x" + "77" * 32
HTTP_SERVICE_COMMAND = [sys.executable, str(REPO_ROOT / "committee" / "signer_service" / "http_service.py")]


def sha256_digest(path: Path) -> str:
    return "0x" + hashlib.sha256(path.read_bytes()).hexdigest()


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
            body = json.dumps({"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1}).encode()
            request = urllib_request.Request(
                rpc_url,
                data=body,
                headers={"Content-Type": "application/json"},
            )
            with urllib_request.urlopen(request, timeout=1.0) as response:
                if "result" in json.loads(response.read().decode()):
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
    raise TimeoutError(f"signer service did not start at {base_url}")


def compute_semantic_root(
    model_digest: str,
    dataset_digest: str,
    training_digest: str,
    metadata_digest: str,
    owner: str,
    path_elements: list[int],
    path_indices: list[int],
) -> int:
    modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    current = (
        (int(model_digest, 16) % modulus)
        + (int(dataset_digest, 16) % modulus) * 2
        + (int(training_digest, 16) % modulus) * 3
        + (int(metadata_digest, 16) % modulus) * 5
        + (int(owner, 16) % modulus) * 7
    ) % modulus
    for level, (element, index) in enumerate(zip(path_elements, path_indices), start=1):
        left = (current + (element - current) * index) % modulus
        right = (element + (current - element) * index) % modulus
        current = (left * 17 + right * 31 + level) % modulus
    return current


def parse_int(value: str | int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    return int(value, 0)


def write_markdown_summary(path: Path, summary: dict) -> None:
    benchmark = summary["benchmark"]
    lines = [
        "# ChainAttest Demo Benchmark Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Attestation bundle time (s) | {benchmark['attestation_bundle_seconds']:.3f} |",
        f"| Attestation relay time (s) | {benchmark['attestation_relay_seconds']:.3f} |",
        f"| Eval bundle time (s) | {benchmark['eval_bundle_seconds']:.3f} |",
        f"| Eval relay time (s) | {benchmark['eval_relay_seconds']:.3f} |",
        f"| Attestation gas used | {benchmark['attestation_gas_used']} |",
        f"| Eval gas used | {benchmark['eval_gas_used']} |",
        "",
        "## Artifact Paths",
        "",
        f"- Attestation package: `{summary['attestation']['package_path']}`",
        f"- Eval package: `{summary['eval']['package_path']}`",
        f"- Coordinator DB: `{summary['artifacts']['db_path']}`",
        f"- Signer audit log: `{summary['artifacts']['signer_audit_log']}`",
    ]
    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local ChainAttest demo flow.")
    parser.add_argument("--output-root", type=Path, default=REPO_ROOT / "artifacts" / "demo")
    parser.add_argument("--rpc-url", type=str, default=None, help="Reuse an existing local RPC URL instead of starting Hardhat.")
    parser.add_argument("--signer-url", type=str, default=None, help="Reuse an existing HTTP signer service instead of starting one.")
    args = parser.parse_args()

    output_root = args.output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    samples_dir = output_root / "samples"
    attestation_dir = output_root / "attestation"
    eval_dir = output_root / "eval"
    state_dir = output_root / "state"
    samples_dir.mkdir(parents=True, exist_ok=True)
    attestation_dir.mkdir(parents=True, exist_ok=True)
    eval_dir.mkdir(parents=True, exist_ok=True)
    state_dir.mkdir(parents=True, exist_ok=True)

    os.environ[SUBMITTER_ENV] = DEPLOYER_PRIVATE_KEY
    os.environ[COMMITTEE_ENV_1] = COMMITTEE_PRIVATE_KEYS[0]
    os.environ[COMMITTEE_ENV_2] = COMMITTEE_PRIVATE_KEYS[1]
    os.environ[EVALUATOR_ENV] = EVALUATOR_PRIVATE_KEY
    os.environ[AUTH_TOKEN_ENV] = "chainattest-demo-token"

    node_process = None
    signer_process = None
    rpc_url = args.rpc_url
    signer_url = args.signer_url

    try:
        if rpc_url is None:
            rpc_port = allocate_port()
            rpc_url = f"http://127.0.0.1:{rpc_port}"
            node_process = subprocess.Popen(
                [NPX_BIN, "hardhat", "node", "--hostname", "127.0.0.1", "--port", str(rpc_port)],
                cwd=REPO_ROOT / "contracts",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            wait_for_rpc(rpc_url)

        committee_addresses = [wallet_address(key) for key in COMMITTEE_PRIVATE_KEYS]
        evaluator_address = wallet_address(EVALUATOR_PRIVATE_KEY)

        fixture = run_bridge(
            {
                "action": "deploy_destination_fixture",
                "rpcUrl": rpc_url,
                "privateKey": DEPLOYER_PRIVATE_KEY,
                "adapterId": ADAPTER_ID,
                "committeeThreshold": 2,
                "committeeSigners": committee_addresses,
                "authorizedEvaluators": [evaluator_address],
            }
        )

        if signer_url is None:
            signer_port = allocate_port()
            signer_url = f"http://127.0.0.1:{signer_port}"
            signer_policy_path = output_root / "signer-policy.json"
            signer_policy_path.write_text(
                json.dumps(
                    {
                        "allowed_actions": ["approve", "sign_eval_attestation", "submit_destination_package"],
                        "allowed_destination_chains": [str(fixture["chainId"])],
                        "allowed_verifiers": [
                            fixture["committeeAuthAdapter"],
                            fixture["semanticVerifier"],
                            fixture["evalThresholdVerifier"],
                        ],
                        "allowed_package_kinds": ["attestation", "eval"],
                        "allowed_evaluators": [evaluator_address],
                        "allowed_submitters": [wallet_address(DEPLOYER_PRIVATE_KEY)],
                    },
                    indent=2,
                )
                + "\n"
            )
            signer_env = os.environ.copy()
            signer_env["CHAINATTEST_SIGNER_HOST"] = "127.0.0.1"
            signer_env["CHAINATTEST_SIGNER_PORT"] = str(signer_port)
            signer_env["CHAINATTEST_SIGNER_AUTH_TOKEN"] = os.environ[AUTH_TOKEN_ENV]
            signer_env["CHAINATTEST_SIGNER_POLICY_PATH"] = str(signer_policy_path)
            signer_env["CHAINATTEST_SIGNER_AUDIT_LOG"] = str(output_root / "signer-audit.jsonl")
            signer_process = subprocess.Popen(
                HTTP_SERVICE_COMMAND,
                cwd=REPO_ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=signer_env,
            )
            wait_for_http_health(signer_url)

        coordinator = CoordinatorService(
            state_path=state_dir / "jobs.json",
            audit_log_path=state_dir / "audit.jsonl",
            db_path=state_dir / "chainattest.db",
        )

        model_path = samples_dir / "model.bin"
        metadata_path = samples_dir / "metadata.json"
        training_path = samples_dir / "training.json"
        dataset_path = samples_dir / "dataset.json"
        model_path.write_bytes(b"chainattest-demo-model-v1")
        metadata_path.write_text('{"arch":"mlp","framework":"demo"}\n')
        training_path.write_text('{"epochs":5,"optimizer":"adam"}\n')
        dataset_path.write_text('{"split":"train","name":"demo-benchmark"}\n')

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

        attestation_request = AttestationBundleRequest(
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
            output_dir=attestation_dir,
            destination_chain_id=int(fixture["chainId"]),
            destination_rpc_url=rpc_url,
            destination_submitter_key_env=SUBMITTER_ENV,
            destination_verifier_address=fixture["semanticVerifier"],
            committee_verifier_address=fixture["committeeAuthAdapter"],
            committee_key_envs=[COMMITTEE_ENV_1, COMMITTEE_ENV_2],
            committee_threshold=2,
            signer_service_url=signer_url,
            signer_service_token_env=AUTH_TOKEN_ENV,
        )

        start = time.perf_counter()
        attestation_bundle = coordinator.prepare_attestation_bundle(attestation_request)
        attestation_bundle_seconds = time.perf_counter() - start

        start = time.perf_counter()
        attestation_submission = coordinator.submit_package(
            SubmissionRequest(
                package_path=Path(attestation_bundle["package_path"]),
                package_kind="attestation",
                destination_rpc_url=rpc_url,
                destination_verifier_address=fixture["semanticVerifier"],
                destination_submitter_secret_ref=f"env:{SUBMITTER_ENV}",
                signer_service_url=signer_url,
                signer_service_token_env=AUTH_TOKEN_ENV,
            )
        )
        attestation_relay_seconds = time.perf_counter() - start

        eval_request = EvalBundleRequest(
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
            evaluator=evaluator_address,
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
            output_dir=eval_dir,
            destination_chain_id=int(fixture["chainId"]),
            destination_rpc_url=rpc_url,
            destination_submitter_key_env=SUBMITTER_ENV,
            destination_verifier_address=fixture["evalThresholdVerifier"],
            committee_verifier_address=fixture["committeeAuthAdapter"],
            committee_key_envs=[COMMITTEE_ENV_1, COMMITTEE_ENV_2],
            committee_threshold=2,
            eval_verifier_address=fixture["evalThresholdVerifier"],
            evaluator_key_env=EVALUATOR_ENV,
            signer_service_url=signer_url,
            signer_service_token_env=AUTH_TOKEN_ENV,
        )

        start = time.perf_counter()
        eval_bundle = coordinator.prepare_eval_bundle(eval_request)
        eval_bundle_seconds = time.perf_counter() - start

        start = time.perf_counter()
        eval_submission = coordinator.submit_package(
            SubmissionRequest(
                package_path=Path(eval_bundle["package_path"]),
                package_kind="eval",
                destination_rpc_url=rpc_url,
                destination_verifier_address=fixture["evalThresholdVerifier"],
                destination_submitter_secret_ref=f"env:{SUBMITTER_ENV}",
                signer_service_url=signer_url,
                signer_service_token_env=AUTH_TOKEN_ENV,
            )
        )
        eval_relay_seconds = time.perf_counter() - start

        attestation_package = json.loads(Path(attestation_bundle["package_path"]).read_text())
        eval_package = json.loads(Path(eval_bundle["package_path"]).read_text())
        attestation_verification = run_bridge(
            {
                "action": "query_destination_verification",
                "rpcUrl": rpc_url,
                "packageKind": "attestation",
                "verifierAddress": fixture["semanticVerifier"],
                "package": attestation_package,
            }
        )
        eval_verification = run_bridge(
            {
                "action": "query_destination_verification",
                "rpcUrl": rpc_url,
                "packageKind": "eval",
                "verifierAddress": fixture["evalThresholdVerifier"],
                "package": eval_package,
            }
        )

        summary = {
            "rpc_url": rpc_url,
            "signer_url": signer_url,
            "fixture": fixture,
            "attestation": {
                "bundle": attestation_bundle,
                "submission": attestation_submission,
                "verified": attestation_verification["verified"],
                "package_path": attestation_bundle["package_path"],
            },
            "eval": {
                "bundle": eval_bundle,
                "submission": eval_submission,
                "verified": eval_verification["verified"],
                "package_path": eval_bundle["package_path"],
            },
            "benchmark": {
                "attestation_bundle_seconds": attestation_bundle_seconds,
                "attestation_relay_seconds": attestation_relay_seconds,
                "eval_bundle_seconds": eval_bundle_seconds,
                "eval_relay_seconds": eval_relay_seconds,
                "attestation_gas_used": parse_int(attestation_submission["metadata"]["receipt"].get("gasUsed")),
                "eval_gas_used": parse_int(eval_submission["metadata"]["receipt"].get("gasUsed")),
            },
            "artifacts": {
                "output_root": str(output_root),
                "db_path": str(state_dir / "chainattest.db"),
                "audit_log": str(state_dir / "audit.jsonl"),
                "signer_audit_log": str(output_root / "signer-audit.jsonl"),
            },
        }

        summary_path = output_root / "demo_summary.json"
        markdown_path = output_root / "benchmark_summary.md"
        summary_path.write_text(json.dumps(summary, indent=2) + "\n")
        write_markdown_summary(markdown_path, summary)
        print(json.dumps(summary, indent=2))
    finally:
        if signer_process is not None:
            signer_process.terminate()
            try:
                signer_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                signer_process.kill()
        if node_process is not None:
            node_process.terminate()
            try:
                node_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                node_process.kill()


if __name__ == "__main__":
    main()
