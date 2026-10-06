from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
from pathlib import Path
from typing import Any

import typer
from rich import print

app = typer.Typer(help="ChainAttest CLI helpers for manifests, witnesses, and relay packages.")

BN254_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
ZERO_BYTES32 = "0x" + "00" * 32
MAX_EVAL_BATCHES = 4
EVAL_COUNT_LIMIT = 2**32
MAX_THRESHOLD_BPS = 10_000
EVAL_PACKAGE_VERSION = 2
EVAL_CIRCUIT_VERSION = 4
EVAL_PUBLIC_SIGNAL_COUNT = 8
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


def fresh_blinding() -> int:
    # A uniformly random BN254 field element. Small or reused blindings make the
    # Poseidon commitments brute-forceable over the few possible scores.
    return secrets.randbelow(BN254_FIELD_MODULUS)


def validate_blinding(value: int, name: str) -> int:
    if not 0 <= value < BN254_FIELD_MODULUS:
        raise typer.BadParameter(f"{name} must be a BN254 field element in [0, p)")
    return value


def normalize_address(address: str) -> str:
    if not address.startswith("0x"):
        raise typer.BadParameter("addresses must be 0x-prefixed")
    if len(address) != 42:
        raise typer.BadParameter("addresses must be 20-byte hex strings")
    return address.lower()


def resolve_source_registry(source_registry: str | None, source_system_id: str) -> str:
    if source_registry is not None:
        return normalize_address(source_registry)
    if source_system_id == ZERO_BYTES32:
        raise typer.BadParameter("source-registry is required when source-system-id is not provided")
    return run_bridge(
        {"action": "normalized_external_registry", "sourceSystemId": source_system_id}
    )["sourceRegistry"]


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
    for index in indices:
        if index not in (0, 1):
            raise typer.BadParameter("path-indices must be binary values")

    # The Poseidon leaf and Merkle root are computed by the crypto bridge so the
    # witness matches the circuit exactly (Python has no matching Poseidon).
    witness_data = run_bridge(
        {
            "action": "semantic_witness",
            "modelFileDigest": record["model_file_digest"],
            "datasetCommitment": record["dataset_commitment"],
            "trainingCommitment": record["training_commitment"],
            "metadataDigest": record["metadata_digest"],
            "owner": record["owner"],
            "attestationId": str(attestation_id),
            "registeredAtBlock": str(registered_at_block),
            "pathElements": [str(value) for value in elements],
            "pathIndices": [str(value) for value in indices],
        }
    )

    expected_root = int(record["weights_root"])
    computed_root = int(witness_data["weightsRoot"])
    if computed_root != expected_root:
        raise typer.BadParameter(
            f"computed weights root {computed_root} does not match manifest weights_root {expected_root}"
        )

    witness = {
        "attestation_id": str(attestation_id),
        "registered_at_block": str(registered_at_block),
        "weights_root": str(expected_root),
        "attestation_commitment": witness_data["attestationCommitment"],
        "circuit_version_id": "1",
        "model_file_digest_field": witness_data["modelFileDigestField"],
        "dataset_commitment_field": witness_data["datasetCommitmentField"],
        "training_commitment_field": witness_data["trainingCommitmentField"],
        "metadata_digest_field": witness_data["metadataDigestField"],
        "owner_field": witness_data["ownerField"],
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
    transcript_version: int = typer.Option(2, help="Transcript schema version"),
    batch_correct_counts: str = typer.Option(..., help="Comma-separated per-batch correct counts"),
    batch_incorrect_counts: str = typer.Option(..., help="Comma-separated per-batch incorrect counts"),
    batch_abstain_counts: str = typer.Option("", help="Comma-separated per-batch abstain counts (default: none)"),
    threshold_bps: int = typer.Option(..., help="Threshold in basis points"),
    min_sample_count: int = typer.Option(1, help="Public lower bound the hidden sample count must meet"),
    evaluator: str = typer.Option(..., help="Evaluator EVM address"),
    evaluator_policy_digest: str = typer.Option(..., help="0x bytes32 evaluator policy digest"),
    evaluator_policy_version: int = typer.Option(1, help="Evaluator policy version"),
    output: Path = typer.Option(..., help="Output private eval claim manifest path"),
) -> None:
    """Record the evaluator's private structured summary; its counts never leave it in plaintext."""
    correct_counts = parse_csv_ints(batch_correct_counts)
    incorrect_counts = parse_csv_ints(batch_incorrect_counts)
    abstain_counts = parse_csv_ints(batch_abstain_counts) or [0] * len(correct_counts)
    if len(correct_counts) != len(incorrect_counts) or len(correct_counts) != len(abstain_counts):
        raise typer.BadParameter("batch count lists must have the same number of entries")
    if not correct_counts:
        raise typer.BadParameter("at least one batch summary is required")
    if len(correct_counts) > MAX_EVAL_BATCHES:
        raise typer.BadParameter(f"at most {MAX_EVAL_BATCHES} batches are supported")
    for counts in (correct_counts, incorrect_counts, abstain_counts):
        if any(not 0 <= count < EVAL_COUNT_LIMIT for count in counts):
            raise typer.BadParameter("batch counts must be integers in [0, 2^32)")
    batch_totals = [sum(batch) for batch in zip(correct_counts, incorrect_counts, abstain_counts)]
    if any(total == 0 for total in batch_totals):
        raise typer.BadParameter("every batch must contain at least one sample")
    if not 0 <= threshold_bps <= MAX_THRESHOLD_BPS:
        raise typer.BadParameter("threshold-bps must be in [0, 10000]")
    if not 1 <= min_sample_count < EVAL_COUNT_LIMIT:
        raise typer.BadParameter("min-sample-count must be in [1, 2^32)")
    if sum(batch_totals) < min_sample_count:
        raise typer.BadParameter("the batch summary has fewer samples than min-sample-count")

    evaluator_address = normalize_address(evaluator)
    manifest = {
        "attestation_id": str(attestation_id),
        "benchmark_digest": benchmark_digest,
        "dataset_split_digest": dataset_split_digest,
        "inference_config_digest": inference_config_digest,
        "randomness_seed_digest": randomness_seed_digest,
        "transcript_version": transcript_version,
        "batch_correct_counts": correct_counts,
        "batch_incorrect_counts": incorrect_counts,
        "batch_abstain_counts": abstain_counts,
        "threshold_bps": threshold_bps,
        "min_sample_count": min_sample_count,
        "evaluator": evaluator_address,
        "evaluator_key_id": run_bridge({"action": "evaluator_key_id", "evaluator": evaluator_address})[
            "evaluatorKeyId"
        ],
        "evaluator_policy_digest": evaluator_policy_digest,
        "evaluator_policy_version": evaluator_policy_version,
    }
    dump_json(output, manifest)
    print(f"[green]Wrote private eval claim manifest to[/green] {output}")


@app.command("build-eval-input")
def build_eval_input(
    manifest: Path = typer.Option(..., help="Private eval claim manifest JSON"),
    output: Path = typer.Option(..., help="Output eval witness JSON (the private commitment opening)"),
    transcript_blinding: int | None = typer.Option(
        None, help="Transcript blinding r_T; omit to sample a fresh random one (recommended)"
    ),
    score_blinding: int | None = typer.Option(
        None, help="Score blinding r_S; omit to sample a fresh random one (recommended)"
    ),
) -> None:
    claim = load_json(manifest)
    r_t = fresh_blinding() if transcript_blinding is None else validate_blinding(transcript_blinding, "transcript-blinding")
    r_s = fresh_blinding() if score_blinding is None else validate_blinding(score_blinding, "score-blinding")
    witness = run_bridge(
        {
            "action": "eval_witness",
            "attestationId": claim["attestation_id"],
            "benchmarkDigest": claim["benchmark_digest"],
            "datasetSplitDigest": claim["dataset_split_digest"],
            "inferenceConfigDigest": claim["inference_config_digest"],
            "randomnessSeedDigest": claim["randomness_seed_digest"],
            "transcriptVersion": str(claim["transcript_version"]),
            "batchCorrectCounts": [str(value) for value in claim["batch_correct_counts"]],
            "batchIncorrectCounts": [str(value) for value in claim["batch_incorrect_counts"]],
            "batchAbstainCounts": [str(value) for value in claim["batch_abstain_counts"]],
            "thresholdBps": str(claim["threshold_bps"]),
            "minSampleCount": str(claim["min_sample_count"]),
            "transcriptBlinding": str(r_t),
            "scoreBlinding": str(r_s),
        }
    )
    dump_json(output, witness)
    print(f"[green]Wrote private eval witness (commitment opening) to[/green] {output}")


@app.command("export-score-opening")
def export_score_opening(
    witness: Path = typer.Option(..., help="Private eval witness JSON from build-eval-input"),
    output: Path = typer.Option(..., help="Output score opening JSON to hand to an auditor"),
) -> None:
    """Extract only (K, N, r_S) from the witness, leaving the per-batch transcript private."""
    data = load_json(witness)
    batches = zip(data["batch_correct_counts"], data["batch_incorrect_counts"], data["batch_abstain_counts"])
    opening = {
        "correct_total": str(sum(int(value) for value in data["batch_correct_counts"])),
        "sample_total": str(sum(int(c) + int(i) + int(a) for c, i, a in batches)),
        "score_blinding": data["score_blinding"],
        "score_commitment": data["score_commitment"],
    }
    dump_json(output, opening)
    print(f"[green]Wrote score opening to[/green] {output}")


@app.command("verify-score-opening")
def verify_score_opening(
    package: Path = typer.Option(..., help="Published eval relay package JSON"),
    opening: Path = typer.Option(..., help="Score opening JSON from export-score-opening"),
) -> None:
    """Check that a disclosed (K, N, r_S) opens the score commitment in a published package."""
    published = load_json(package)
    disclosed = load_json(opening)
    correct_total = int(disclosed["correct_total"])
    sample_total = int(disclosed["sample_total"])
    result = run_bridge(
        {
            "action": "eval_score_opening",
            "correctTotal": str(correct_total),
            "sampleTotal": str(sample_total),
            "scoreBlinding": disclosed["score_blinding"],
            "scoreCommitment": str(published["scoreCommitment"]),
        }
    )
    if not result["matches"] or sample_total == 0:
        print("[red]Opening does not match the published score commitment[/red]")
        raise typer.Exit(code=1)
    print(
        f"[green]Score commitment opens to[/green] {correct_total}/{sample_total} "
        f"({correct_total * 10_000 // sample_total} bps)"
    )


def load_optional_json(path: Path | None) -> Any:
    if path is None:
        return None
    return load_json(path)


def zero_groth16_proof() -> dict[str, Any]:
    return {
        "pA": ["0", "0"],
        "pB": [["0", "0"], ["0", "0"]],
        "pC": ["0", "0"],
    }


def zero_public_signals(length: int) -> list[str]:
    return ["0"] * length


def load_registered_package(path: Path, expected_type: int, package_name: str) -> dict[str, Any]:
    package = load_json(path)
    actual_type = package.get("packageType")
    if actual_type != expected_type:
        raise typer.BadParameter(
            f"{package_name} must reference a package with packageType {expected_type}, got {actual_type}"
        )
    return package


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
    source_registry: str | None = typer.Option(None),
    source_system_id: str = typer.Option(ZERO_BYTES32),
    source_channel_id: str = typer.Option(ZERO_BYTES32),
    source_tx_id: str = typer.Option(ZERO_BYTES32),
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
        "sourceSystemId": source_system_id,
        "sourceChannelId": source_channel_id,
        "sourceTxId": source_tx_id,
        "sourceRegistry": resolve_source_registry(source_registry, source_system_id),
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


@app.command("render-attestation-revoke-package")
def render_attestation_revoke_package(
    registered_package: Path = typer.Option(..., help="Previously rendered attestation package JSON"),
    source_tx_id: str = typer.Option(..., help="Revocation source transaction id as bytes32 hex"),
    source_block_number: int = typer.Option(..., help="Revocation source block number"),
    source_block_hash: str = typer.Option(..., help="Revocation source block hash as bytes32 hex"),
    signatures_file: Path | None = typer.Option(None, help="Optional committee signature JSON"),
    output: Path = typer.Option(..., help="Output revoke package JSON"),
) -> None:
    package = load_registered_package(registered_package, 0, "registered-package")
    revoke_package = {
        **package,
        "packageType": 1,
        "sourceTxId": source_tx_id,
        "sourceBlockNumber": str(source_block_number),
        "sourceBlockHash": source_block_hash,
        "signatures": load_optional_json(signatures_file) or [],
        "proof": zero_groth16_proof(),
        "publicSignals": zero_public_signals(5),
    }
    dump_json(output, revoke_package)
    print(f"[green]Wrote attestation revoke package to[/green] {output}")


@app.command("render-eval-package")
def render_eval_package(
    manifest: Path = typer.Option(..., help="Eval claim manifest JSON"),
    eval_input: Path = typer.Option(..., help="Eval witness input JSON"),
    source_chain_id: int = typer.Option(...),
    source_registry: str | None = typer.Option(None),
    source_system_id: str = typer.Option(ZERO_BYTES32),
    source_channel_id: str = typer.Option(ZERO_BYTES32),
    source_tx_id: str = typer.Option(ZERO_BYTES32),
    source_block_number: int = typer.Option(...),
    source_block_hash: str = typer.Option(...),
    claimed_at_block: int = typer.Option(...),
    adapter_id: str = typer.Option(...),
    finality_delay_blocks: int = typer.Option(...),
    eval_circuit_version: int = typer.Option(EVAL_CIRCUIT_VERSION),
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

    # Only commitments, the threshold, the sample-size floor, and the verdict leave
    # the private manifest and witness; no count is copied into the package.
    package = {
        "packageVersion": EVAL_PACKAGE_VERSION,
        "packageType": 2,
        "sourceChainId": str(source_chain_id),
        "sourceSystemId": source_system_id,
        "sourceChannelId": source_channel_id,
        "sourceTxId": source_tx_id,
        "sourceRegistry": resolve_source_registry(source_registry, source_system_id),
        "sourceBlockNumber": str(source_block_number),
        "sourceBlockHash": source_block_hash,
        "attestationId": claim["attestation_id"],
        "benchmarkDigest": claim["benchmark_digest"],
        "transcriptCommitment": eval_witness["transcript_commitment"],
        "scoreCommitment": eval_witness["score_commitment"],
        "thresholdBps": claim["threshold_bps"],
        "minSampleCount": claim["min_sample_count"],
        "verdict": int(eval_witness["verdict"]),
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


@app.command("render-eval-revoke-package")
def render_eval_revoke_package(
    registered_package: Path = typer.Option(..., help="Previously rendered eval package JSON"),
    source_tx_id: str = typer.Option(..., help="Revocation source transaction id as bytes32 hex"),
    source_block_number: int = typer.Option(..., help="Revocation source block number"),
    source_block_hash: str = typer.Option(..., help="Revocation source block hash as bytes32 hex"),
    signatures_file: Path | None = typer.Option(None, help="Optional committee signature JSON"),
    output: Path = typer.Option(..., help="Output revoke package JSON"),
) -> None:
    package = load_registered_package(registered_package, 2, "registered-package")
    revoke_package = {
        **package,
        "packageType": 3,
        "sourceTxId": source_tx_id,
        "sourceBlockNumber": str(source_block_number),
        "sourceBlockHash": source_block_hash,
        "signatures": load_optional_json(signatures_file) or [],
        "evaluatorSignature": "0x",
        "proof": zero_groth16_proof(),
        "publicSignals": zero_public_signals(EVAL_PUBLIC_SIGNAL_COUNT),
    }
    dump_json(output, revoke_package)
    print(f"[green]Wrote eval revoke package to[/green] {output}")


@app.command("query-attestation")
def query_attestation(attestation_id: int) -> None:
    print(f"[yellow]Stub:[/yellow] query attestation_id={attestation_id} against a source or destination registry")


if __name__ == "__main__":
    app()
