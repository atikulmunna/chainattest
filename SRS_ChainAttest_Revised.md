# Software Requirements Specification (SRS)
## ChainAttest
## Trust-Minimized Cross-Chain ML Attestation Relay

---

| Field | Details |
|-------|---------|
| Document ID | SRS-CHAINATTEST-REV-001 |
| Version | 2.0.0-draft |
| Status | Revised Draft |
| Date | 2026-04-08 |
| Authoring Basis | Revised from original `SRS_CrossChain_ML_Attestation_Bridge.md` |
| Primary Goal | Build a research-grade system for relaying and verifying ML attestations across chains with privacy-preserving evaluation claims |
| MVP Scope | EVM source -> EVM destination |
| Primary Stack | Solidity, Circom, TypeScript, Python |
| Future Adapters | Fabric source adapter, Solana destination adapter, source light-client / ZK adapter |

---

## Table of Contents

1. Executive Summary
2. Purpose and Scope
3. Design Principles
4. Problem Statement and Positioning
5. Goals and Non-Goals
6. System Context
7. Trust Model and Security Assumptions
8. High-Level Architecture
9. Canonical Data Model and Hash Semantics
10. Cryptographic Design
11. Source Authenticity Layer
12. Smart Contract Specification
13. Off-Chain Services Specification
14. CLI and API Specification
15. Functional Requirements
16. Non-Functional Requirements
17. Threat Model
18. Compliance Evidence Framing
19. Evaluation Plan
20. Phased Delivery Plan
21. Acceptance Criteria
22. Open Questions and Future Work
23. Appendix

---

## 1. Executive Summary

ChainAttest is a cross-chain relay system for machine learning attestations. Its payload is not tokens and not arbitrary bytes. Its payload is typed evidence about ML artifacts: model identity, weight commitments, provenance commitments, evaluation claim commitments, lineage references, and revocation state.

The revised design preserves five central novelty claims:

- ML attestations as the relay payload rather than assets
- ZK relations over ML-specific commitments rather than consensus headers
- privacy-preserving evaluation attestations with threshold proofs
- compliance-evidence infrastructure for AI governance and traceability
- heterogeneous and permissioned-to-public extensions as a defined adapter roadmap

This revision intentionally avoids over-claiming. The system is not described as fully trustless unless the source-authenticity adapter itself is trustless. The MVP uses an explicit threshold-signature authenticity adapter. A later phase may replace that adapter with a source-chain light client or ZK inclusion proof.

The design separates three proof layers:

1. Source authenticity: did this attestation really originate from the declared source registry after finality?
2. Semantic integrity: does the attestation commitment match a well-formed ML attestation structure?
3. Evaluation privacy: can the model owner prove a hidden evaluation score exceeds a public threshold without revealing the exact score?

This separation keeps the novelty focused on semantic attestations, private evaluation, and governance evidence, while making the cross-chain trust assumptions precise and publishable.

---

## 2. Purpose and Scope

### 2.1 Purpose

This document defines the software requirements for ChainAttest, a system that enables one blockchain to verify ML-specific attestations that originated on another blockchain.

The document is intended for:

- protocol and smart contract engineers
- zero-knowledge engineers
- ML platform engineers
- security reviewers
- academic collaborators

### 2.2 In-Scope for MVP

The MVP includes:

- a source-chain model registry on an EVM chain
- a destination-chain verifier on an EVM chain
- a threshold-signature source-authenticity adapter
- ZK circuits for attestation semantics and evaluation threshold proofs
- a relayer / coordinator service
- a CLI for registration, proof generation, relay, and verification
- structured metadata committed off-chain and referenced from-chain

### 2.3 Explicitly Out of Scope for MVP

The MVP does not include:

- general token bridging
- generic arbitrary message passing
- proving source-chain block inclusion inside the main semantic circuit
- full ML training correctness proofs
- private model inference proofs
- decentralized proving markets
- Fabric and Solana production support

### 2.4 Scope for Research Extensions

Later phases may add:

- a ZK or light-client source-authenticity adapter
- permissioned source chain support
- Solana destination support
- batch / aggregated proof verification
- evaluator attestation marketplaces

---

## 3. Design Principles

The revised system follows these principles:

### 3.1 Separate Novelty from Plumbing

Semantic attestation logic and privacy-preserving evaluation are the research core. Cross-chain transport and source authentication are modular infrastructure layers.

### 3.2 Be Precise About Trust

Every verification result must clearly state what was trusted:

- a threshold committee
- a source light client
- a ZK source inclusion proof

### 3.3 Do Not Mix Hash Semantics Accidentally

Different hash functions serve different roles:

- SHA-256 for file and artifact identity
- Keccak-256 for EVM-native typed message hashing
- Poseidon for circuit-friendly commitments

The system must never imply these are interchangeable.

### 3.4 Privacy Is Selective, Not Absolute

The system protects hidden evaluation scores and undisclosed artifact internals. It does not guarantee total metadata secrecy if a deployment chooses public metadata fields.

### 3.5 Publishable Architecture over Maximal Scope

The MVP should be cohesive, reproducible, benchmarkable, and defensible in a paper. Anything that threatens this is deferred.

---

## 4. Problem Statement and Positioning

### 4.1 Problem

Organizations increasingly need to prove facts about ML systems across administrative and blockchain boundaries:

- that a model artifact corresponds to a registered identity
- that a training run references a documented dataset commitment
- that evaluation was performed against a named benchmark
- that performance exceeds a policy threshold
- that the above evidence can be inspected from a destination environment without exposing private weights or exact scores

Existing cross-chain bridges focus on assets or general messages. Existing ML provenance systems usually stop at single-chain or off-chain registries. The gap is not just transport. The gap is semantic attestation relay: moving typed ML evidence across chains while preserving provenance structure, enabling selective disclosure of evaluation claims, and making the source-authenticity assumption explicit.

### 4.2 Positioning

ChainAttest is best positioned as:

- a semantic attestation relay for ML governance
- a privacy-preserving evaluation evidence layer
- a modular cross-chain protocol where source authenticity is pluggable

It should not be positioned as:

- a replacement for canonical cross-chain asset bridges
- a proof that a model is safe or legally compliant
- a proof that training was performed correctly end-to-end

### 4.3 Novelty Contributions

The paper should use careful language such as "to our knowledge" and present the following novelty claims.

#### Novelty 1: Attestations, Not Assets

ChainAttest is designed to relay structured ML attestations rather than tokens, balances, or opaque message payloads. Its core object is a typed evidence record containing model identity commitments, provenance commitments, evaluation claim commitments, lineage references, and revocation state. This makes the protocol semantically different from conventional asset bridges and generic message relays.

#### Novelty 2: ZK Relations Over ML-Specific Commitments

The semantic proof layer reasons about ML artifact commitments rather than consensus headers or token transfer state. The circuits are designed around model-weight commitments, training-related commitments, metadata commitments, and evaluation-linked commitments. In the revised architecture, this novelty is made cleaner by separating semantic proof relations from source-authenticity verification rather than mixing both into one circuit.

#### Novelty 3: Privacy-Preserving Evaluation Attestations

ChainAttest supports threshold proofs for evaluation claims where the exact score remains hidden while a public threshold claim is verified. The revised design strengthens this novelty by binding the proof not only to a model attestation but also to a benchmark digest and evaluation transcript digest, making the claim specific, auditable, and selectively disclosable.

#### Novelty 4: Compliance-Evidence Infrastructure for AI Governance

ChainAttest provides tamper-evident, cross-chain evidence anchoring for model identity, provenance, and evaluation-related claims. This is positioned as compliance-evidence infrastructure for auditability, traceability, and selective disclosure in AI governance settings. The claim is intentionally framed as evidence support, not as automatic legal compliance.

#### Novelty 5: Heterogeneous and Permissioned-to-Public Extensions

A key forward-looking extension of ChainAttest is support for heterogeneous chain pairs, especially permissioned-source to public-destination deployments. In the revised SRS this is preserved as an adapter roadmap rather than an MVP claim. That keeps the first implementation credible while retaining the longer-term differentiated research direction of enterprise or consortium-origin attestations becoming publicly verifiable.

---

## 5. Goals and Non-Goals

### 5.1 Goals

- enable a source-chain registry to commit ML attestation records
- enable a destination-chain verifier to verify attestation relay packages
- support hidden-score threshold proofs
- bind evaluation claims to a specific model and benchmark context
- make trust assumptions explicit and queryable
- provide reproducible benchmarks and open artifacts

### 5.2 Non-Goals

- proving model accuracy from first principles
- proving benchmark dataset integrity on-chain
- proving every field in a model card is truthful
- replacing enterprise governance workflows
- guaranteeing regulator acceptance

---

## 6. System Context

### 6.1 Stakeholders

| Stakeholder | Role |
|------------|------|
| ML Engineer | Registers model artifacts and evaluation claims |
| Platform Operator | Runs source registry, relayer, and committee nodes |
| Auditor | Queries destination-chain verification state |
| Downstream Contract | Enforces policy based on verified attestations |
| Researcher | Benchmarks and extends circuits or adapters |

### 6.2 Primary User Story

1. An ML engineer trains or packages a model.
2. The CLI canonicalizes the artifact and computes commitments.
3. The source registry stores the attestation commitments.
4. A source-authenticity adapter attests that the source record is finalized.
5. A relayer assembles the relay package.
6. The destination verifier checks source authenticity and semantic validity.
7. Any party queries the destination chain for verification status and trust mode.

### 6.3 Evaluation Claim User Story

1. The model owner runs evaluation off-chain.
2. The evaluator or platform produces an evaluation transcript digest.
3. The model owner computes a commitment to the exact score.
4. A ZK proof shows the committed exact score exceeds a public threshold.
5. The destination chain records that the threshold claim is valid for the given model and benchmark context.

---

## 7. Trust Model and Security Assumptions

### 7.1 Core Revision

The system is not inherently trustless. Its trust properties depend on the configured source-authenticity adapter.

### 7.2 Supported Trust Modes

| Trust Mode | Description | MVP | Trust Assumption |
|-----------|-------------|-----|------------------|
| Committee | Threshold signatures over finalized source records | Yes | At least threshold committee members are honest |
| Light Client | Destination verifies source finality / inclusion | No | Source consensus assumptions only |
| ZK Source Adapter | ZK proof of inclusion and finality | No | Circuit soundness and source consensus assumptions |

### 7.3 Security Statement for MVP

For the MVP, a destination-chain verification result means:

"A valid semantic attestation package was verified, and a threshold of the configured source-authenticity committee signed the source record after the configured finality delay."

It does not mean:

- the source chain was verified trustlessly on the destination chain
- the evaluation itself was independently rerun
- the benchmark transcript contents were publicly disclosed

### 7.4 Honest Assumptions

MVP security assumes:

- the source registry contract is correct
- at least `t` committee signers are honest
- the circuit implementation matches the documented relation
- the trusted setup is not compromised
- the evaluator transcript digest corresponds to a real benchmark run when such a digest is used

### 7.5 Queryable Trust Metadata

Every verified destination record must expose:

- source authenticity mode
- committee threshold or adapter identifier
- source chain ID
- source registry address
- source block number or finality epoch
- verifier / circuit version

---

## 8. High-Level Architecture

### 8.1 Components

| Component | Type | Responsibility |
|----------|------|----------------|
| `ModelRegistry` | Source-chain contract | Stores ML attestation commitments and evaluation claim commitments |
| `CommitteeAuthAdapter` | Source-chain / off-chain hybrid | Produces threshold signatures over finalized source records |
| `SemanticVerifier` | Destination-chain contract | Verifies semantic attestation proofs and records verified state |
| `EvalThresholdVerifier` | Destination-chain contract | Verifies threshold proofs for hidden scores |
| `Coordinator` | Off-chain service | Watches source events, assembles relay packages, submits proofs |
| `chain-attest` CLI | Off-chain client | Hashing, registration, proof generation, queries, exports |
| Metadata Store | IPFS / Arweave / object store | Stores rich metadata and transcripts referenced by commitments |

### 8.2 Architecture Diagram

```text
                         +----------------------------+
                         |        ML Engineer         |
                         |  chain-attest register     |
                         |  chain-attest prove-eval   |
                         +-------------+--------------+
                                       |
                                       v
                         +----------------------------+
                         |       Source Registry      |
                         |       ModelRegistry        |
                         |  stores commitments only   |
                         +-------------+--------------+
                                       |
                         source event  |  finalized record
                                       v
              +------------------------+------------------------+
              |                 Coordinator                     |
              |  - source event listener                        |
              |  - metadata fetcher                             |
              |  - witness builder                              |
              |  - package assembler                            |
              |  - destination submitter                        |
              +------------------------+------------------------+
                                       |
                        relay package  |
                                       v
      +----------------------------+       +----------------------------+
      | CommitteeAuthAdapter       |       | ZK Proof System            |
      | threshold signatures over  |       | semantic proof + eval      |
      | source record commitment   |       | threshold proof            |
      +-------------+--------------+       +-------------+--------------+
                    \\                                  /
                     \\                                /
                      \\                              /
                       v                            v
                       +----------------------------+
                       |   Destination Verifiers    |
                       | SemanticVerifier           |
                       | EvalThresholdVerifier      |
                       +-------------+--------------+
                                     |
                                     v
                       +----------------------------+
                       | Any verifier or contract   |
                       | query verified state       |
                       +----------------------------+
```

### 8.3 Relay Package Concept

A relay package is the unit submitted to the destination chain. It contains:

- source record identifiers
- source-authenticity proof material
- semantic proof material
- circuit public inputs
- versioning metadata

This package is typed and versioned. It is not a generic byte blob.

---

## 9. Canonical Data Model and Hash Semantics

### 9.1 Why This Section Exists

The original draft mixed SHA-256, Keccak-256, and Poseidon in ways that would not compose cleanly. The revised design assigns each hash function one role.

### 9.2 Artifact and Commitment Types

| Name | Type | Hash / Encoding | Purpose |
|------|------|-----------------|---------|
| `model_file_digest` | bytes32 | SHA-256 | Identity of canonical serialized model package |
| `layer_commitment_i` | field element | Poseidon | Circuit-friendly commitment of layer `i` |
| `weights_root` | field element | Poseidon Merkle root | Commitment to model layer set |
| `dataset_commitment` | bytes32 | SHA-256 or Keccak-256 | Commitment to dataset manifest or dataset snapshot metadata |
| `training_commitment` | bytes32 | SHA-256 | Commitment to training config manifest |
| `metadata_digest` | bytes32 | SHA-256 | Commitment to canonical metadata JSON |
| `eval_transcript_digest` | bytes32 | SHA-256 | Commitment to canonical evaluation transcript |
| `score_commitment` | field element | Poseidon(exact_score, salt) | Hidden evaluation score commitment |
| `attestation_commitment` | field element | Poseidon over normalized fields | Circuit-friendly semantic commitment |
| `evm_typed_hash` | bytes32 | Keccak-256 / EIP-712 | EVM-native typed signing and committee signing |

### 9.3 Canonical Serialization Rules

All off-chain manifests must use canonical serialization:

- UTF-8 JSON
- lexicographically sorted keys
- no insignificant whitespace
- fixed numeric precision rules
- explicit schema version
- field omission forbidden unless documented

### 9.4 Model Packaging Rules

The CLI must package the model artifact deterministically before hashing:

- normalize framework-specific containers where possible
- include framework and version in the manifest
- include layer ordering
- include tensor names, shapes, dtypes, and chunking rules

If deterministic packaging is impossible for a model format, the CLI must reject the format or label it experimental.

### 9.5 Attestation Record Structure

The canonical attestation record contains:

```json
{
  "schema_version": "2.0",
  "source_chain_id": 11155111,
  "registry_address": "0xRegistry",
  "attestation_id": 42,
  "model": {
    "model_file_digest": "0x...",
    "weights_root": "0x...",
    "framework": "onnx",
    "framework_version": "1.16.0",
    "architecture_label": "resnet50",
    "parameter_count": 25557032
  },
  "training": {
    "dataset_commitment": "0x...",
    "training_commitment": "0x...",
    "metadata_digest": "0x..."
  },
  "ownership": {
    "owner_address": "0xOwner",
    "parent_attestation_id": 0
  },
  "timestamps": {
    "registered_at_block": 123456,
    "registered_at_unix": 1775600000
  }
}
```

### 9.6 Evaluation Claim Structure

The canonical evaluation claim contains:

```json
{
  "schema_version": "2.0",
  "source_chain_id": 11155111,
  "attestation_id": 42,
  "benchmark_id": "imagenet-val-2024",
  "benchmark_digest": "0x...",
  "eval_transcript_digest": "0x...",
  "score_commitment": "0x...",
  "threshold_bps": 9000,
  "evaluator_id": "benchmark-lab-01",
  "claimed_at_block": 123500
}
```

### 9.7 Attestation Semantic Commitment

The semantic commitment is the circuit-facing digest over normalized fields:

```text
attestation_commitment =
  Poseidon(
    attestation_id,
    weights_root,
    field(model_file_digest),
    field(dataset_commitment),
    field(training_commitment),
    field(metadata_digest),
    field(owner_address),
    registered_at_block
  )
```

Because some inputs are `bytes32`, the implementation must define a deterministic `bytes32 -> field` mapping. This mapping must be documented, versioned, and tested across TypeScript, Python, Solidity helper libraries, and circuit witness generation.

### 9.8 EVM Typed Hash

For EVM-native signatures, the system defines an EIP-712 relay message:

```text
RelayMessage {
  uint256 sourceChainId
  address registry
  uint256 attestationId
  uint256 sourceBlockNumber
  bytes32 evmTypedHash
  bytes32 adapterId
}
```

Committee signers sign the EIP-712 relay message after the finality window has elapsed.

The circuit does not recompute EIP-712. That is an EVM-native layer, not a circuit relation.

---

## 10. Cryptographic Design

### 10.1 Proof Layer Separation

The protocol uses independent relations:

1. Semantic attestation relation
2. Evaluation threshold relation
3. Source-authenticity verification relation

The destination chain verifies them together at the protocol layer, not by forcing all logic into one circuit.

### 10.2 Semantic Attestation Relation

The semantic attestation proof demonstrates:

- a model layer leaf is consistent with the committed `weights_root`, or
- a selected subset of artifact commitments is internally consistent with `attestation_commitment`

The exact relation is implementation-versioned. For MVP version `sem-v1`, the circuit proves:

- the provided `weights_root` is derived from a Merkle path and a private layer commitment
- the provided `attestation_commitment` is Poseidon over the normalized source attestation fields
- the public `attestation_id` and `registered_at_block` are bound into that commitment

This gives semantic structure, not source finality.

### 10.3 Evaluation Threshold Relation

The evaluation threshold proof demonstrates:

- the prover knows `exact_score` and `salt`
- `score_commitment = Poseidon(exact_score, salt)`
- `exact_score >= threshold_bps`
- `0 <= exact_score <= 10000`
- the proof is bound to `attestation_id`, `benchmark_digest`, and `eval_transcript_digest`

This fixes the weakness of proving only "some score is above threshold" without binding it to the relevant benchmark context.

### 10.4 Circuit Interface: `semantic_attestation.circom`

Public inputs:

- `attestation_id`
- `registered_at_block`
- `weights_root`
- `attestation_commitment`
- `circuit_version_id`

Private inputs:

- selected normalized field elements
- `leaf_commitment`
- Merkle path elements
- Merkle path indices

Required constraints:

- Merkle inclusion is valid
- `attestation_commitment` equals Poseidon over normalized fields
- the normalized fields include the public `attestation_id` and `registered_at_block`

### 10.5 Circuit Interface: `eval_threshold.circom`

Public inputs:

- `attestation_id`
- `benchmark_digest`
- `eval_transcript_digest`
- `score_commitment`
- `threshold_bps`
- `circuit_version_id`

Private inputs:

- `exact_score`
- `salt`

Required constraints:

- `score_commitment = Poseidon(exact_score, salt)`
- `exact_score >= threshold_bps`
- `exact_score <= 10000`

### 10.6 Optional Aggregation

Aggregation is deferred from the MVP. If implemented later:

- aggregation must not change the semantic meaning of individual attestation records
- aggregation must preserve per-record queryability
- batch claims must be benchmarked against single-proof verification

### 10.7 Trusted Setup

The MVP uses Groth16 with circuit-specific Phase 2 setup.

Requirements:

- use a publicly documented Phase 1 Powers of Tau artifact
- perform at least three independent Phase 2 contributions for production artifacts
- publish transcript logs, final `.zkey`, verification key, and circuit hashes

### 10.8 Cryptographic Versioning

Each proof-verifiable artifact must have explicit version IDs:

- semantic circuit version
- evaluation circuit version
- field-normalization version
- source-authenticity adapter version

No contract upgrade may silently reinterpret old commitments.

---

## 11. Source Authenticity Layer

### 11.1 Motivation

The destination chain must know whether the attestation actually originated from the declared source registry. This problem is distinct from semantic correctness.

### 11.2 MVP Adapter: CommitteeAuthAdapter

The MVP source-authenticity adapter uses a threshold committee.

#### 11.2.1 Committee Model

- `n` committee signers are registered on destination chain
- threshold `t` is configurable
- each signer has an EOA or smart-contract wallet
- committee rotation is admin-controlled and time-delayed

Recommended default:

- `n = 5`
- `t = 3`

#### 11.2.2 What the Committee Signs

Signers must sign:

```text
SourceRecordApproval {
  source_chain_id,
  registry_address,
  source_block_number,
  source_block_hash,
  attestation_id,
  message_type,
  semantic_commitment_or_eval_claim_hash,
  finality_delay_blocks,
  adapter_version
}
```

#### 11.2.3 Finality Delay

The coordinator must not request signatures until:

- the configured finality delay in source blocks has elapsed
- the source record has not been revoked

Default for testnet MVP:

- `finality_delay_blocks = 12`

### 11.3 Destination Verification Rules

The destination verifier must reject a package unless:

- at least `t` distinct valid signatures are present
- the signed message matches the package contents exactly
- the signer set corresponds to the configured adapter version
- the attestation or evaluation claim is not already superseded or revoked

### 11.4 Future Adapters

The destination verifier should expose an adapter interface so later implementations can support:

- source light-client adapter
- ZK source inclusion adapter
- permissioned chain notarization adapter

### 11.5 Adapter Interface

```solidity
interface ISourceAuthAdapter {
    function verifySourceRecord(bytes calldata packageData)
        external
        view
        returns (
            bool ok,
            bytes32 sourceRecordHash,
            bytes32 adapterId,
            uint256 sourceChainId,
            uint256 sourceBlockNumber
        );
}
```

---

## 12. Smart Contract Specification

### 12.1 Source Contract: `ModelRegistry`

Purpose:

- register model attestations
- register evaluation claim commitments
- manage revocation and lineage

#### 12.1.1 Source Data Structures

```solidity
struct AttestationRecord {
    uint256 attestationId;
    bytes32 modelFileDigest;
    uint256 weightsRoot;
    bytes32 datasetCommitment;
    bytes32 trainingCommitment;
    bytes32 metadataDigest;
    address owner;
    uint256 parentAttestationId;
    uint64 registeredAtBlock;
    uint64 registeredAtTime;
    bool revoked;
}

struct EvalClaimRecord {
    uint256 attestationId;
    bytes32 benchmarkDigest;
    bytes32 evalTranscriptDigest;
    uint256 scoreCommitment;
    uint32 thresholdBps;
    bytes32 evaluatorKeyId;
    uint64 claimedAtBlock;
    bool revoked;
}
```

#### 12.1.2 Source Events

```solidity
event AttestationRegistered(
    uint256 indexed attestationId,
    address indexed owner,
    bytes32 modelFileDigest,
    uint256 weightsRoot,
    bytes32 metadataDigest
);

event EvalClaimRegistered(
    uint256 indexed attestationId,
    bytes32 indexed benchmarkDigest,
    bytes32 evalTranscriptDigest,
    uint256 scoreCommitment,
    uint32 thresholdBps
);

event AttestationRevoked(uint256 indexed attestationId, address indexed actor);
event EvalClaimRevoked(uint256 indexed attestationId, bytes32 indexed benchmarkDigest, address indexed actor);
```

#### 12.1.3 Source Functions

Required functions:

- `registerAttestation(...)`
- `registerEvalClaim(...)`
- `revokeAttestation(attestationId)`
- `revokeEvalClaim(attestationId, benchmarkDigest)`
- `getAttestation(attestationId)`
- `getEvalClaim(attestationId, benchmarkDigest)`

#### 12.1.4 Source Rules

- only owner may add or revoke its evaluation claims unless admin override exists
- revoking an attestation implicitly invalidates downstream evaluation claims
- parent lineage must reference an existing prior attestation

### 12.2 Destination Contract: `SemanticVerifier`

Purpose:

- verify relay packages for attestation records
- store verification state plus trust metadata

#### 12.2.1 Destination Data Structures

```solidity
struct VerifiedAttestation {
    uint256 attestationId;
    uint256 sourceChainId;
    address sourceRegistry;
    uint256 sourceBlockNumber;
    bytes32 sourceRecordHash;
    bytes32 adapterId;
    uint256 weightsRoot;
    uint256 attestationCommitment;
    uint32 semanticCircuitVersion;
    bool revoked;
    uint64 verifiedAt;
}
```

#### 12.2.2 Destination Functions

- `verifyAttestationPackage(...)`
- `markRevoked(...)`
- `isVerified(attestationId, sourceChainId, sourceRegistry)`
- `getVerifiedAttestation(...)`

#### 12.2.3 Verification Procedure

`verifyAttestationPackage(...)` must:

1. verify source authenticity through the configured adapter
2. verify the semantic ZK proof using the registered semantic verifier key
3. confirm the package fields match between adapter inputs and proof public inputs
4. store the verified record keyed by `(sourceChainId, sourceRegistry, attestationId)`

### 12.3 Destination Contract: `EvalThresholdVerifier`

Purpose:

- verify evaluation threshold relay packages
- bind them to previously verified attestations

#### 12.3.1 Destination Data Structures

```solidity
struct VerifiedEvalClaim {
    uint256 attestationId;
    uint256 sourceChainId;
    address sourceRegistry;
    bytes32 benchmarkDigest;
    bytes32 evalTranscriptDigest;
    uint256 scoreCommitment;
    uint32 thresholdBps;
    bytes32 adapterId;
    uint32 evalCircuitVersion;
    bool revoked;
    uint64 verifiedAt;
}
```

#### 12.3.2 Verification Rules

The contract must reject an evaluation package unless:

- the corresponding attestation is already verified
- source authenticity succeeds for the evaluation claim
- the evaluation proof succeeds
- the public inputs match the relay package contents

### 12.4 Admin and Upgrade Controls

The revised system should prefer immutability for verifier logic where possible.

If upgrades are used:

- upgrades must be timelocked
- circuit version changes must register new verification keys
- old records must remain interpretable

Roles:

| Role | Responsibility |
|------|----------------|
| `DEFAULT_ADMIN_ROLE` | register adapters, signer sets, and verification keys |
| `COMMITTEE_ADMIN_ROLE` | rotate committee signer sets under timelock |
| `REGISTRY_ADMIN_ROLE` | emergency pause for source registry only if required |
| Public user | submit valid relay packages |

### 12.5 Replay Protection

The destination contracts must include replay protection based on:

- source chain ID
- source registry address
- attestation ID or evaluation claim key
- adapter ID
- source block number

### 12.6 Revocation Semantics

Revocation is a first-class protocol action, not an off-chain convention.

Requirements:

- revocation records must travel through the source-authenticity adapter
- destination queries must distinguish `verified`, `revoked`, and `never_verified`
- downstream contracts must be able to require `verified && !revoked`

---

## 13. Off-Chain Services Specification

### 13.1 Coordinator Service

The coordinator is an untrusted orchestrator. It may assemble packages and pay gas, but it must not have privileged authority over verification outcomes.

Responsibilities:

- listen for source registry events
- wait for finality delay
- gather metadata digests and claim parameters
- request committee signatures if committee mode is enabled
- build circuit witnesses
- generate proofs or invoke proving service
- submit destination transactions
- persist state and retries

### 13.2 Committee Signer Service

Each committee signer service:

- watches source records
- enforces finality delay
- signs only records consistent with its policy
- logs every signed record for audit

### 13.3 Prover Mode

The system supports two prover modes:

| Mode | Description |
|------|-------------|
| Client-side | model owner generates private proofs locally |
| Coordinator-side | coordinator generates proofs from provided witness material |

Default recommendation:

- semantic proof may be coordinator-side if only non-sensitive inputs are required
- evaluation threshold proof should be client-side whenever exact score privacy matters

### 13.4 State Storage

The coordinator must persist:

- last processed source block
- pending jobs
- proof generation status
- committee signature collection status
- destination tx status

### 13.5 Metadata Storage

Rich metadata may be stored in:

- IPFS
- Arweave
- enterprise object storage

Regardless of location, on-chain records store only commitments or references.

### 13.6 Failure Handling

Coordinator requirements:

- idempotent resubmission
- exponential backoff
- proof artifact cleanup on failure
- replay missed events after restart

---

## 14. CLI and API Specification

### 14.1 CLI Commands

```text
chain-attest register-attestation
chain-attest register-eval-claim
chain-attest prove-eval-threshold
chain-attest relay-attestation
chain-attest relay-eval-claim
chain-attest query-attestation
chain-attest query-eval-claim
chain-attest revoke-attestation
chain-attest revoke-eval-claim
chain-attest export-evidence
chain-attest hash-model
chain-attest hash-metadata
chain-attest coordinator start
chain-attest coordinator status
```

### 14.2 Example: Register Attestation

```bash
chain-attest register-attestation \
  --model ./artifacts/model.onnx \
  --metadata ./manifests/model_metadata.json \
  --training ./manifests/training_manifest.json \
  --dataset ./manifests/dataset_manifest.json \
  --rpc $SOURCE_RPC \
  --registry 0xRegistry
```

Expected output:

- `attestation_id`
- `model_file_digest`
- `weights_root`
- `dataset_commitment`
- `training_commitment`
- `metadata_digest`
- source transaction hash

### 14.3 Example: Register Evaluation Claim

```bash
chain-attest register-eval-claim \
  --attestation-id 42 \
  --benchmark ./benchmarks/imagenet_val_2024.json \
  --transcript ./eval/transcript.json \
  --score-commitment 0x... \
  --threshold-bps 9000 \
  --rpc $SOURCE_RPC
```

### 14.4 Example: Prove Threshold Privately

```bash
chain-attest prove-eval-threshold \
  --attestation-id 42 \
  --benchmark-digest 0x... \
  --eval-transcript-digest 0x... \
  --exact-score 9234 \
  --threshold-bps 9000 \
  --salt-file ./secrets/eval_salt.txt \
  --circuit ./circuits/eval_threshold.wasm
```

### 14.5 Example: Relay Attestation

```bash
chain-attest relay-attestation \
  --attestation-id 42 \
  --source sepolia \
  --dest holesky \
  --adapter committee-v1
```

### 14.6 Query Semantics

The query command must return:

- verification state
- revocation state
- source authenticity mode
- adapter ID
- circuit version
- source block reference

### 14.7 Export Evidence

`export-evidence` must produce a machine-readable report with:

- attestation identifiers
- commitments and references
- source authenticity details
- evaluation threshold claim details
- destination verification status

The exported report must avoid claiming legal compliance by itself.

### 14.8 Health API

Coordinator health API:

`GET /health`

Response fields:

- `status`
- `source_chain_id`
- `last_processed_block`
- `queue_depth`
- `pending_signature_requests`
- `proof_jobs_in_progress`
- `last_successful_submission`
- `adapter_mode`

---

## 15. Functional Requirements

### 15.1 Source Registry Requirements

#### FR-SR-01 Register Attestation

- The system shall allow an owner to register an attestation record on the source chain.
- The record shall include the canonical commitment fields defined in Section 9.
- The source chain shall emit an `AttestationRegistered` event.

#### FR-SR-02 Deterministic Canonicalization

- The CLI shall canonicalize model and metadata inputs deterministically.
- The CLI shall reject unsupported formats that cannot be canonicalized reliably.

#### FR-SR-03 Register Evaluation Claim Commitment

- The source registry shall accept a claim commitment for an evaluation threshold claim.
- The exact score shall not be written on-chain.

#### FR-SR-04 Lineage Support

- The source registry shall allow an attestation to reference a parent attestation.
- The parent must exist or the transaction must revert.

#### FR-SR-05 Revocation

- Owners shall be able to revoke their own attestation records and evaluation claim records.
- The source registry shall emit explicit revocation events.

### 15.2 Source Authenticity Requirements

#### FR-SA-01 Threshold Signature Collection

- The coordinator shall be able to collect threshold committee signatures for a finalized source record.

#### FR-SA-02 Finality Delay Enforcement

- The coordinator and signer services shall not approve a source record before the configured finality delay.

#### FR-SA-03 Adapter Verification

- The destination chain shall reject any relay package whose source-authenticity adapter check fails.

#### FR-SA-04 Trust Metadata Exposure

- Destination query functions shall expose which adapter verified the record.

### 15.3 Semantic Verification Requirements

#### FR-SV-01 Semantic Proof Verification

- The destination chain shall verify a semantic proof against the registered semantic verifier key.

#### FR-SV-02 Public Input Consistency

- The destination chain shall confirm that the public inputs used by the semantic proof match the package contents.

#### FR-SV-03 Record Storage

- Successful verification shall store a destination record keyed by source chain, source registry, and attestation ID.

#### FR-SV-04 Idempotency

- Re-submitting an already verified identical package shall not create duplicate records.

### 15.4 Evaluation Threshold Requirements

#### FR-EV-01 Threshold Proof

- The system shall support a proof that a hidden exact score exceeds a public threshold.

#### FR-EV-02 Binding to Benchmark Context

- The threshold proof shall be bound to a benchmark digest and evaluation transcript digest.

#### FR-EV-03 Binding to Model Identity

- The threshold proof shall be bound to the attestation ID of a previously verified attestation.

#### FR-EV-04 Destination Verification

- The destination chain shall verify evaluation proofs only after the corresponding attestation is verified.

#### FR-EV-05 Revocation Propagation

- Revocation of an evaluation claim on the source chain shall be reflected on the destination chain.

### 15.5 Coordinator Requirements

#### FR-CO-01 Source Event Listener

- The coordinator shall listen for attestation and evaluation events from the source registry.

#### FR-CO-02 Persistent Job State

- The coordinator shall persist jobs and resume them after restart.

#### FR-CO-03 Retry Logic

- Failed proof-generation or submission jobs shall retry with bounded exponential backoff.

#### FR-CO-04 Multi-Role Separation

- The coordinator shall support running event listening, proof generation, and transaction submission as separable processes.

#### FR-CO-05 Safe Resubmission

- The coordinator shall avoid nonce collisions and shall support idempotent submission behavior.

### 15.6 CLI Requirements

#### FR-CLI-01 Hash Commands

- The CLI shall compute canonical digests for model packages and metadata manifests.

#### FR-CLI-02 Local Proof Generation

- The CLI shall support local generation of evaluation threshold proofs.

#### FR-CLI-03 Query Commands

- The CLI shall query both source and destination state and present verification, revocation, and trust metadata.

#### FR-CLI-04 Evidence Export

- The CLI shall export machine-readable evidence bundles.

---

## 16. Non-Functional Requirements

### 16.1 Performance

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-P-01 | Semantic circuit proof generation | < 60s on reference 8-core machine |
| NFR-P-02 | Evaluation threshold proof generation | < 20s on reference 8-core machine |
| NFR-P-03 | Destination semantic verification gas | < 450k gas |
| NFR-P-04 | Destination evaluation verification gas | < 450k gas |
| NFR-P-05 | End-to-end relay latency after finality delay | < 5 minutes on testnet |
| NFR-P-06 | Coordinator restart recovery | < 30s to resume processing |

### 16.2 Security

| ID | Requirement |
|----|-------------|
| NFR-S-01 | Private keys shall never be stored in plaintext config files |
| NFR-S-02 | Committee signer actions shall be auditable |
| NFR-S-03 | False proof acceptance probability shall be negligible under circuit soundness assumptions |
| NFR-S-04 | Destination verification shall not depend on coordinator trust |
| NFR-S-05 | Evaluation exact score shall remain hidden from on-chain observers |

### 16.3 Correctness

| ID | Requirement |
|----|-------------|
| NFR-C-01 | Hashes and commitments shall match across CLI, contracts, and witness builders |
| NFR-C-02 | Public input packing shall be versioned and deterministic |
| NFR-C-03 | Invalid Merkle paths shall always fail proof verification |
| NFR-C-04 | Threshold proof for `exact_score < threshold` shall fail |
| NFR-C-05 | Query results shall distinguish `verified`, `revoked`, and `unknown` |

### 16.4 Maintainability

| ID | Requirement |
|----|-------------|
| NFR-M-01 | Every verifier key shall be registered with a version ID |
| NFR-M-02 | Every adapter shall be registered with a version ID |
| NFR-M-03 | Circuit and serialization changes shall not silently reinterpret old records |
| NFR-M-04 | Integration test coverage shall include end-to-end happy path and adversarial cases |

### 16.5 Reproducibility

| ID | Requirement |
|----|-------------|
| NFR-R-01 | Benchmarks shall be reproducible from a documented script entrypoint |
| NFR-R-02 | Trusted setup artifacts and circuit hashes shall be published |
| NFR-R-03 | Benchmark environment details shall be recorded with each run |

---

## 17. Threat Model

### 17.1 Assets

| Asset | Sensitivity | Notes |
|------|-------------|-------|
| Model file digest | Medium | Public identifier of the canonical model package |
| Weights root | Medium | Public commitment to model layers |
| Exact evaluation score | High | Hidden behind threshold proof |
| Evaluation salt | Critical | Needed to preserve score hiding |
| Committee keys | Critical | Control source-authenticity approvals |
| Trusted setup toxic waste | Critical | Can break proof soundness if compromised |
| Verification state on destination chain | Critical | Downstream policy may rely on it |

### 17.2 Threat Actors

| Actor | Capability |
|------|------------|
| Malicious model owner | attempts to register misleading metadata or fake evaluation claims |
| Coordinator operator | delays, censors, or reorders package submission |
| Committee minority | signs invalid packages below threshold |
| Committee threshold adversary | signs false source records if threshold compromised |
| On-chain observer | attempts to infer hidden score or sensitive metadata |
| Contract attacker | exploits logic or access-control bugs |
| Setup attacker | attempts to retain toxic waste or tamper with artifacts |

### 17.3 Major Threats and Mitigations

| Threat | Mitigation |
|--------|------------|
| False source-origin claim | threshold signatures or future source-verification adapter |
| Semantic mismatch between proof and package | strict public-input consistency checks |
| Proof replay | replay protection keyed by source identifiers and versions |
| Hidden score disclosure via prover | recommend client-side proving for evaluation claims |
| Committee compromise | explicit trust statement, signer rotation, timelocks, audit logs |
| Malicious metadata mutation | canonical digests and immutable content addressing |
| Revocation suppression | source revocation events plus relay package support for revocations |

### 17.4 Known Residual Risk in MVP

The committee-based MVP inherits committee trust. This is not a bug in the design. It is an explicit tradeoff to keep the semantic and privacy contributions implementable and measurable.

---

## 18. Compliance Evidence Framing

### 18.1 Framing

ChainAttest is a compliance-evidence system, not a legal compliance engine.

It can support:

- traceability
- tamper-evident evidence anchoring
- selective disclosure of threshold claims
- lineage and revocation tracking

It does not itself determine whether a model satisfies legal obligations.

### 18.2 Evidence Mapping

| Evidence Need | ChainAttest Capability |
|--------------|------------------------|
| Model identity traceability | canonical model digests and destination verification |
| Training documentation anchoring | training and metadata commitments |
| Benchmark evidence anchoring | evaluation transcript digest |
| Public auditability | destination-chain verified state |
| Confidential performance disclosure | threshold proof over hidden exact score |

### 18.3 Reporting Requirements

Any report generated by the CLI must:

- list source and destination records
- identify the trust mode used
- list all commitments and references
- state that off-chain artifacts remain required for full audit
- avoid phrases such as "EU AI Act compliant" unless a human reviewer adds that conclusion separately

---

## 19. Evaluation Plan

### 19.1 Core Metrics

The system shall benchmark:

- semantic circuit constraints
- evaluation circuit constraints
- proof generation time
- verification gas
- end-to-end latency
- committee signature collection latency
- destination storage overhead

### 19.2 Security Evaluation

The system shall evaluate:

- invalid semantic proofs
- invalid threshold proofs
- mismatched public inputs
- replay attempts
- stale or revoked source records
- insufficient committee signatures

### 19.3 Usability Evaluation

The system should report:

- number of CLI steps required to register and verify
- time to generate evidence bundle
- failure clarity for unsupported model formats

### 19.4 Comparative Evaluation

The paper should compare against:

- naive single-chain registry
- non-private cross-chain message relay
- committee-authenticated relay without semantic proof

This comparison better isolates the contribution than comparing only to token bridges.

---

## 20. Phased Delivery Plan

### Phase 1: Focused MVP (Weeks 1-8)

Goal:

- EVM source -> EVM destination
- committee source-authenticity adapter
- semantic proof
- private threshold proof
- reproducible benchmarks

Deliverables:

- source and destination contracts
- committee signer service
- coordinator
- CLI
- two Circom circuits
- E2E testnet demo

### Phase 2: Hardening and Paper-Ready Evaluation (Weeks 9-14)

Goal:

- adversarial tests
- performance tuning
- benchmark suite
- evidence export
- formal protocol write-up

Deliverables:

- benchmark corpus
- security analysis
- public artifacts
- draft paper figures and tables

### Phase 3: Adapter Expansion (Future Work)

Possible work:

- ZK or light-client source adapter
- Fabric source adapter
- Solana destination adapter
- proof aggregation

This phase is explicitly outside the core acceptance path for the first paper.

---

## 21. Acceptance Criteria

The revised MVP is complete when all of the following are true:

1. An attestation can be registered on the source chain with deterministic commitments.
2. A threshold committee can approve the finalized source record.
3. A destination package can be verified and stored with explicit trust metadata.
4. An evaluation claim can be registered with a hidden exact score commitment.
5. A threshold proof can demonstrate `score >= threshold` while keeping the exact score private.
6. Revocation propagates and is queryable on the destination chain.
7. End-to-end tests cover valid and invalid packages.
8. Benchmark scripts reproduce proof-time and gas results.

---

## 22. Open Questions and Future Work

### 22.1 Open Questions

- Should semantic proof `sem-v1` prove one layer inclusion, a sampled subset, or full manifest consistency?
- Should evaluation transcript digests require evaluator signatures in MVP or only in Phase 2?
- Is committee signing done fully off-chain, or should the source chain emit approval checkpoints?
- Should destination records be immutable or upgradeable under versioned registries?

### 22.2 Future Work

- trustless source verification via light clients or ZK inclusion
- support for permissioned source chains
- support for non-EVM destinations
- richer attestation schemas for deployment authorization and model retirement
- evaluator attestation networks

---

## 23. Appendix

### 23.1 Suggested Repository Layout

```text
chainattest/
  contracts/
    src/
      ModelRegistry.sol
      SemanticVerifier.sol
      EvalThresholdVerifier.sol
      adapters/
        CommitteeAuthAdapter.sol
    test/
  circuits/
    semantic_attestation.circom
    eval_threshold.circom
    scripts/
  coordinator/
    chainattest_coordinator/
  cli/
    chain_attest/
  committee/
    signer_service/
  schemas/
    attestation.schema.json
    eval_claim.schema.json
  benchmarks/
  docs/
    SRS_ChainAttest_Revised.md
```

### 23.2 Minimum Test Matrix

Required contract tests:

- register attestation
- revoke attestation
- verify valid package
- reject wrong adapter signatures
- reject wrong proof public inputs
- reject replayed package
- revoke verified destination record

Required circuit tests:

- valid semantic proof
- invalid Merkle path
- altered public input
- valid threshold proof
- score below threshold fails
- wrong score commitment fails

Required E2E tests:

- register -> approve -> relay -> verify
- register eval claim -> prove threshold -> relay -> verify
- revoke attestation -> relay revoke -> destination state updates

### 23.3 Paper Abstract Seed

The revised SRS supports a paper framed roughly as:

"We present ChainAttest, a trust-minimized cross-chain relay protocol for machine-learning attestations. Unlike traditional bridges that transport assets or opaque messages, ChainAttest relays typed ML evidence including model identity commitments, provenance commitments, evaluation claim commitments, lineage, and revocation state. The protocol introduces zero-knowledge relations over ML-specific commitments rather than consensus headers, supports privacy-preserving evaluation attestations through threshold proofs bound to benchmark and transcript digests, and frames cross-chain verification as compliance-evidence infrastructure for AI governance. To keep trust assumptions explicit, ChainAttest separates source authenticity from semantic verification through a modular adapter layer, while preserving heterogeneous and permissioned-to-public deployment as an extension path. We implement an EVM-to-EVM prototype and evaluate proof cost, gas overhead, and end-to-end relay latency."

### 23.4 Revision Summary from Original Draft

This revision intentionally changes the original direction in the following ways:

- narrows the MVP to EVM -> EVM
- replaces blanket "trustless" language with explicit trust modes
- separates source authenticity from semantic verification
- fixes hash-role ambiguity between SHA-256, Keccak-256, and Poseidon
- strengthens evaluation proof binding to benchmark and transcript context
- reframes compliance as evidence anchoring rather than automatic compliance
- moves Fabric and Solana to future adapters rather than MVP promises
