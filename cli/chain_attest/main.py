from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import typer
from rich import print

app = typer.Typer(help="ChainAttest CLI helpers for manifests, witnesses, and relay packages.")

BN254_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
REPO_ROOT = Path(__file__).resolve().parents[2]
CRYPTO_BRIDGE = Path(__file__).resolve().with_name("crypto_bridge.js")


def sha256_digest(path: Path) -> str:
    return "0x" + hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def dump_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def field_from_hex(hex_value: str) -> int:
    return int(hex_value, 16) % BN254_FIELD_MODULUS


def parse_csv_ints(values: str) -> list[int]:
    return [int(part.strip()) for part in values.split(",") if part.strip()]


def normalize_address(address: str) -> str:
    if not address.startswith("0x"):
        raise typer.BadParameter("addresses must be 0x-prefixed")
    if len(address) != 42:
        raise typer.BadParameter("addresses must be 20-byte hex strings")
    return address.lower()


def run_bridge(payload: dict[str, Any]) -> dict[str, Any]:
    result = subprocess.run(
        ["node", str(CRYPTO_BRIDGE)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
        cwd=REPO_ROOT,
    )
    return json.loads(result.stdout)


@app.command("register-attestation")
def register_attestation(
    model: Path,
    metadata: Path,
    training: Path,
    dataset: Path,
    owner: str = typer.Option(..., help="Owner EVM address"),
    weights_root: int = typer.Option(..., help="Committed weights root from the source record"),
    parent_attestation_id: int = typer.Option(0, help="Optional parent attestation id"),
    output: Path = typer.Option(..., help="Output JSON manifest path"),
) -> None:
    owner_address = normalize_address(owner)
    manifest = {
        "owner": owner_address,
        "weights_root": str(weights_root),
        "parent_attestation_id": str(parent_attestation_id),
        "model_file_digest": sha256_digest(model),
        "dataset_commitment": sha256_digest(dataset),
        "training_commitment": sha256_digest(training),
        "metadata_digest": sha256_digest(metadata),
    }
    dump_json(output, manifest)
    print(f"[green]Wrote attestation manifest to[/green] {output}")


@app.command("build-semantic-input")
def build_semantic_input(
    manifest: Path = typer.Option(..., help="Attestation manifest JSON"),
    attestation_id: int = typer.Option(..., help="Source-chain attestation id"),
    registered_at_block: int = typer.Option(..., help="Source-chain registration block"),
    path_elements: str = typer.Option(..., help="Comma-separated Merkle path elements"),
    path_indices: str = typer.Option(..., help="Comma-separated binary path indices"),
    output: Path = typer.Option(..., help="Output semantic witness JSON"),
) -> None:
    record = load_json(manifest)
    elements = parse_csv_ints(path_elements)
    indices = parse_csv_ints(path_indices)
    if len(elements) != len(indices):
        raise typer.BadParameter("path-elements and path-indices must have the same length")

    model_field = field_from_hex(record["model_file_digest"])
    dataset_field = field_from_hex(record["dataset_commitment"])
    training_field = field_from_hex(record["training_commitment"])
    metadata_field = field_from_hex(record["metadata_digest"])
    owner_field = int(record["owner"], 16) % BN254_FIELD_MODULUS

    current = (
        model_field
        + dataset_field * 2
        + training_field * 3
        + metadata_field * 5
        + owner_field * 7
    ) % BN254_FIELD_MODULUS

    for level, (element, index) in enumerate(zip(elements, indices), start=1):
        if index not in (0, 1):
            raise typer.BadParameter("path-indices must be binary values")
        left = (current + (element - current) * index) % BN254_FIELD_MODULUS
        right = (element + (current - element) * index) % BN254_FIELD_MODULUS
        current = (left * 17 + right * 31 + level) % BN254_FIELD_MODULUS

    expected_root = int(record["weights_root"])
    if current != expected_root:
        raise typer.BadParameter(
            f"computed weights root {current} does not match manifest weights_root {expected_root}"
        )

    attestation_commitment = (
        attestation_id
        + model_field * 3
        + dataset_field * 5
        + training_field * 7
        + metadata_field * 11
        + owner_field * 13
        + registered_at_block * 17
        + expected_root * 19
    ) % BN254_FIELD_MODULUS

    witness = {
        "attestation_id": str(attestation_id),
        "registered_at_block": str(registered_at_block),
        "weights_root": str(expected_root),
        "attestation_commitment": str(attestation_commitment),
        "circuit_version_id": "1",
        "model_file_digest_field": str(model_field),
        "dataset_commitment_field": str(dataset_field),
        "training_commitment_field": str(training_field),
        "metadata_digest_field": str(metadata_field),
        "owner_field": str(owner_field),
        "path_elements": [str(value) for value in elements],
        "path_indices": [str(value) for value in indices],
    }
    dump_json(output, witness)
    print(f"[green]Wrote semantic witness input to[/green] {output}")


@app.command("register-eval-claim")
def register_eval_claim(
    attestation_id: int = typer.Option(..., help="Source attestation id"),
    benchmark_digest: str = typer.Option(..., help="0x bytes32 benchmark digest"),
    dataset_split_digest: str = typer.Option(..., help="0x bytes32 dataset split digest"),
    inference_config_digest: str = typer.Option(..., help="0x bytes32 inference config digest"),
    randomness_seed_digest: str = typer.Option(..., help="0x bytes32 randomness seed digest"),
    transcript_sample_count: int = typer.Option(..., help="Structured transcript sample count"),
    transcript_version: int = typer.Option(1, help="Transcript schema version"),
    threshold_bps: int = typer.Option(..., help="Threshold in basis points"),
    evaluator: str = typer.Option(..., help="Evaluator EVM address"),
    evaluator_policy_digest: str = typer.Option(..., help="0x bytes32 evaluator policy digest"),
    evaluator_policy_version: int = typer.Option(1, help="Evaluator policy version"),
    output: Path = typer.Option(..., help="Output JSON eval manifest path"),
) -> None:
    transcript = run_bridge(
        {
            "action": "transcript_digest",
            "attestationId": str(attestation_id),
            "benchmarkDigest": benchmark_digest,
            "datasetSplitDigest": dataset_split_digest,
            "inferenceConfigDigest": inference_config_digest,
            "randomnessSeedDigest": randomness_seed_digest,
            "transcriptSampleCount": transcript_sample_count,
            "transcriptVersion": transcript_version,
        }
    )

    manifest = {
        "attestation_id": str(attestation_id),
        "benchmark_digest": benchmark_digest,
        "eval_transcript_digest": transcript["evalTranscriptDigest"],
        "dataset_split_digest": dataset_split_digest,
        "inference_config_digest": inference_config_digest,
        "randomness_seed_digest": randomness_seed_digest,
        "transcript_sample_count": transcript_sample_count,
        "transcript_version": transcript_version,
        "threshold_bps": threshold_bps,
        "evaluator": normalize_address(evaluator),
        "evaluator_key_id": transcript["evaluatorKeyId"] if "evaluatorKeyId" in transcript else None,
        "evaluator_policy_digest": evaluator_policy_digest,
        "evaluator_policy_version": evaluator_policy_version,
    }
    manifest["evaluator_key_id"] = run_bridge(
        {"action": "evaluator_key_id", "evaluator": manifest["evaluator"]}
    )["evaluatorKeyId"]
    dump_json(output, manifest)
    print(f"[green]Wrote eval claim manifest to[/green] {output}")


@app.command("build-eval-input")
def build_eval_input(
    manifest: Path = typer.Option(..., help="Eval claim manifest JSON"),
    exact_score: int = typer.Option(..., help="Exact evaluation score in basis points"),
    salt: int = typer.Option(..., help="Private salt field element"),
    output: Path = typer.Option(..., help="Output eval witness JSON"),
) -> None:
    claim = load_json(manifest)
    witness_data = run_bridge(
        {
            "action": "eval_witness",
            "attestationId": claim["attestation_id"],
            "benchmarkDigest": claim["benchmark_digest"],
            "evalTranscriptDigest": claim["eval_transcript_digest"],
            "exactScore": str(exact_score),
            "salt": str(salt),
        }
    )

    witness = {
        "attestation_id": claim["attestation_id"],
        "benchmark_digest_field": witness_data["benchmarkField"],
        "eval_transcript_digest_field": witness_data["evalTranscriptField"],
        "score_commitment": witness_data["scoreCommitment"],
        "threshold_bps": str(claim["threshold_bps"]),
        "circuit_version_id": "1",
        "exact_score": str(exact_score),
        "salt": str(salt),
    }
    dump_json(output, witness)
    print(f"[green]Wrote eval witness input to[/green] {output}")


def load_optional_json(path: Path | None) -> Any:
    if path is None:
        return None
    return load_json(path)


def normalize_groth16_proof(proof: Any) -> Any:
    if proof is None:
        return None
    if isinstance(proof, dict) and {"pA", "pB", "pC"}.issubset(proof.keys()):
        return proof
    return run_bridge({"action": "normalize_groth16_proof", "proof": proof})["proof"]


def normalize_public_signals(values: Any) -> Any:
    if values is None:
        return None
    if not isinstance(values, list):
        raise typer.BadParameter("public signals must be a JSON array")
    return [str(value) for value in values]


@app.command("render-attestation-package")
def render_attestation_package(
    manifest: Path = typer.Option(..., help="Attestation manifest JSON"),
    semantic_input: Path = typer.Option(..., help="Semantic witness input JSON"),
    source_chain_id: int = typer.Option(...),
    source_registry: str = typer.Option(...),
    source_block_number: int = typer.Option(...),
    source_block_hash: str = typer.Option(...),
    registered_at_time: int = typer.Option(...),
    adapter_id: str = typer.Option(...),
    finality_delay_blocks: int = typer.Option(...),
    semantic_circuit_version: int = typer.Option(1),
    proof_file: Path | None = typer.Option(None, help="Optional Groth16 proof JSON"),
    public_signals_file: Path | None = typer.Option(None, help="Optional public signals JSON"),
    signatures_file: Path | None = typer.Option(None, help="Optional committee signature JSON"),
    output: Path = typer.Option(...),
) -> None:
    record = load_json(manifest)
    semantic = load_json(semantic_input)
    proof = normalize_groth16_proof(load_optional_json(proof_file))
    public_signals = normalize_public_signals(load_optional_json(public_signals_file))
    signatures = load_optional_json(signatures_file) or []

    package = {
        "packageVersion": 1,
        "packageType": 0,
        "sourceChainId": str(source_chain_id),
        "sourceRegistry": source_registry,
        "sourceBlockNumber": str(source_block_number),
        "sourceBlockHash": source_block_hash,
        "attestationId": semantic["attestation_id"],
        "modelFileDigest": record["model_file_digest"],
        "weightsRoot": semantic["weights_root"],
        "datasetCommitment": record["dataset_commitment"],
        "trainingCommitment": record["training_commitment"],
        "metadataDigest": record["metadata_digest"],
        "owner": record["owner"],
        "parentAttestationId": record["parent_attestation_id"],
        "registeredAtBlock": semantic["registered_at_block"],
        "registeredAtTime": str(registered_at_time),
        "attestationCommitment": semantic["attestation_commitment"],
        "adapterId": adapter_id,
        "finalityDelayBlocks": str(finality_delay_blocks),
        "signatures": signatures,
        "semanticCircuitVersion": semantic_circuit_version,
        "proof": proof,
        "publicSignals": public_signals,
    }
    dump_json(output, package)
    print(f"[green]Wrote attestation relay package to[/green] {output}")


@app.command("render-eval-package")
def render_eval_package(
    manifest: Path = typer.Option(..., help="Eval claim manifest JSON"),
    eval_input: Path = typer.Option(..., help="Eval witness input JSON"),
    source_chain_id: int = typer.Option(...),
    source_registry: str = typer.Option(...),
    source_block_number: int = typer.Option(...),
    source_block_hash: str = typer.Option(...),
    claimed_at_block: int = typer.Option(...),
    adapter_id: str = typer.Option(...),
    finality_delay_blocks: int = typer.Option(...),
    eval_circuit_version: int = typer.Option(1),
    evaluator_signature: str = typer.Option("0x", help="Optional evaluator signature"),
    proof_file: Path | None = typer.Option(None, help="Optional Groth16 proof JSON"),
    public_signals_file: Path | None = typer.Option(None, help="Optional public signals JSON"),
    signatures_file: Path | None = typer.Option(None, help="Optional committee signature JSON"),
    output: Path = typer.Option(...),
) -> None:
    claim = load_json(manifest)
    eval_witness = load_json(eval_input)
    proof = normalize_groth16_proof(load_optional_json(proof_file))
    public_signals = normalize_public_signals(load_optional_json(public_signals_file))
    signatures = load_optional_json(signatures_file) or []

    package = {
        "packageVersion": 1,
        "packageType": 2,
        "sourceChainId": str(source_chain_id),
        "sourceRegistry": source_registry,
        "sourceBlockNumber": str(source_block_number),
        "sourceBlockHash": source_block_hash,
        "attestationId": claim["attestation_id"],
        "benchmarkDigest": claim["benchmark_digest"],
        "evalTranscriptDigest": claim["eval_transcript_digest"],
        "datasetSplitDigest": claim["dataset_split_digest"],
        "inferenceConfigDigest": claim["inference_config_digest"],
        "randomnessSeedDigest": claim["randomness_seed_digest"],
        "transcriptSampleCount": claim["transcript_sample_count"],
        "transcriptVersion": claim["transcript_version"],
        "scoreCommitment": eval_witness["score_commitment"],
        "thresholdBps": claim["threshold_bps"],
        "evaluator": claim["evaluator"],
        "evaluatorKeyId": claim["evaluator_key_id"],
        "evaluatorPolicyDigest": claim["evaluator_policy_digest"],
        "evaluatorPolicyVersion": claim["evaluator_policy_version"],
        "evaluatorSignature": evaluator_signature,
        "claimedAtBlock": str(claimed_at_block),
        "adapterId": adapter_id,
        "finalityDelayBlocks": str(finality_delay_blocks),
        "signatures": signatures,
        "evalCircuitVersion": eval_circuit_version,
        "proof": proof,
        "publicSignals": public_signals,
    }
    dump_json(output, package)
    print(f"[green]Wrote eval relay package to[/green] {output}")


@app.command("query-attestation")
def query_attestation(attestation_id: int) -> None:
    print(f"[yellow]Stub:[/yellow] query attestation_id={attestation_id} against a source or destination registry")


if __name__ == "__main__":
    app()
