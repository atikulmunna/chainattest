# ChainAttest Protocol and Interface Specification
## MVP Implementation Spec

---

| Field | Details |
|-------|---------|
| Document ID | CHAINATTEST-PROTO-001 |
| Version | 1.0.0-draft |
| Date | 2026-04-08 |
| Derived From | `SRS_ChainAttest_Revised.md` |
| Scope | EVM source -> EVM destination, committee-authenticated MVP |
| Audience | protocol engineers, smart contract developers, relayer engineers, CLI developers, auditors |

---

## Table of Contents

1. Purpose
2. MVP Protocol Summary
3. Naming and Type Conventions
4. Canonical Commitments
5. Source-Chain Contract Interfaces
6. Destination-Chain Contract Interfaces
7. Source Authenticity Adapter Spec
8. ZK Proof Interfaces
9. Relay Package Schemas
10. CLI Command Contract
11. Coordinator API and State
12. Error Model
13. Event and Replay Semantics
14. Versioning Rules
15. Minimum Test Matrix

---

## 1. Purpose

This document translates the revised SRS into implementation-facing protocol details for the MVP.

It defines:

- contract-level interfaces
- wire-format and JSON package schemas
- typed relay package contents
- proof public-input layouts
- coordinator behavior
- CLI command contracts

This document does not redefine the research framing. It is intended to be the working specification used during implementation.

---

## 2. MVP Protocol Summary

The MVP protocol has two verification tracks:

1. Attestation verification
2. Evaluation threshold verification

Both tracks follow the same high-level sequence:

1. A source-chain registry stores a committed record.
2. The coordinator waits for source finality delay.
3. The coordinator obtains threshold committee approvals over a typed source record hash.
4. The coordinator assembles a relay package.
5. The destination verifier checks:
   - source authenticity via the committee adapter
   - the relevant Groth16 proof
   - consistency between package fields and proof public inputs
6. The destination verifier stores normalized verified state.

The destination chain does not trust the coordinator. It only trusts:

- the configured source-authenticity adapter
- the registered verification keys
- contract logic

---

## 3. Naming and Type Conventions

### 3.1 Primitive Types

| Name | Solidity Type | JSON Type | Notes |
|------|---------------|-----------|-------|
| chain ID | `uint256` | decimal string or number | prefer decimal string in JSON |
| attestation ID | `uint256` | decimal string | unique within source registry |
| benchmark digest | `bytes32` | `0x` hex string | SHA-256 or normalized bytes32 digest |
| model file digest | `bytes32` | `0x` hex string | SHA-256 digest |
| field element | `uint256` | decimal string | must be `< BN254 modulus` |
| EVM address | `address` | checksum hex string | EIP-55 |
| unix time | `uint64` | integer | seconds |
| block number | `uint64` or `uint256` | integer | use `uint256` in contract interfaces where convenient |

### 3.2 Normalized Identifiers

The implementation must use these normalized identifiers consistently:

- `attestationId`
- `sourceChainId`
- `sourceRegistry`
- `sourceBlockNumber`
- `weightsRoot`
- `attestationCommitment`
- `benchmarkDigest`
- `evalTranscriptDigest`
- `scoreCommitment`
- `thresholdBps`
- `adapterId`
- `semanticCircuitVersion`
- `evalCircuitVersion`

### 3.3 Message Types

The adapter layer recognizes these message types:

- `ATTESTATION_REGISTER`
- `ATTESTATION_REVOKE`
- `EVAL_CLAIM_REGISTER`
- `EVAL_CLAIM_REVOKE`

Recommended EVM representation:

```solidity
enum MessageType {
    ATTESTATION_REGISTER,
    ATTESTATION_REVOKE,
    EVAL_CLAIM_REGISTER,
    EVAL_CLAIM_REVOKE
}
```

---

## 4. Canonical Commitments

### 4.1 Required Digests

The CLI or packaging layer must compute:

- `modelFileDigest: bytes32`
- `datasetCommitment: bytes32`
- `trainingCommitment: bytes32`
- `metadataDigest: bytes32`
- `benchmarkDigest: bytes32`
- `evalTranscriptDigest: bytes32`

### 4.2 Required Field Commitments

The proof system must compute:

- `weightsRoot: uint256`
- `scoreCommitment: uint256`
- `attestationCommitment: uint256`

### 4.3 Field Mapping Function

All `bytes32 -> field` conversions must use the same rule.

MVP rule:

```text
field(bytes32_value) = uint256(bytes32_value) mod BN254_FIELD_MODULUS
```

Requirements:

- identical implementation in TypeScript, Python, and Solidity helper libraries
- snapshot tests for cross-language equality
- versioned as `field_norm_v1`

### 4.4 Semantic Commitment Layout

The semantic commitment input order for `sem-v1` shall be:

```text
[
  attestationId,
  weightsRoot,
  field(modelFileDigest),
  field(datasetCommitment),
  field(trainingCommitment),
  field(metadataDigest),
  field(ownerAddress),
  registeredAtBlock
]
```

The implementation must not reorder these fields without a new circuit version.

### 4.5 Evaluation Commitment Layout

The evaluation score commitment layout for `eval-v1` shall be:

```text
scoreCommitment = Poseidon([
  attestationId,
  field(benchmarkDigest),
  field(evalTranscriptDigest),
  exactScore,
  salt
])
```

Constraints:

- `exactScore` is basis points in `[0, 10000]`
- `salt` is a field element sampled uniformly from a cryptographically secure RNG
- the evaluator signs a typed evaluation statement over the same attestation and benchmark context

### 4.6 Transcript Commitment Layout

The transcript digest carried by eval packages must not be an opaque hash with no stated semantics.

For the current structured transcript format, the destination verifier recomputes:

```text
evalTranscriptDigest = keccak256(abi.encode(
  attestationId,
  benchmarkDigest,
  datasetSplitDigest,
  inferenceConfigDigest,
  randomnessSeedDigest,
  transcriptSampleCount,
  transcriptVersion
))
```

Requirements:

- `transcriptSampleCount > 0`
- `transcriptVersion` identifies the schema version for the transcript summary
- the evaluator statement must cover the same transcript fields
- eval packages must also carry `evaluatorPolicyDigest` and `evaluatorPolicyVersion` so the evaluator attests to a concrete scoring policy

---

## 5. Source-Chain Contract Interfaces

### 5.1 `IModelRegistry`

```solidity
interface IModelRegistry {
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
        bytes32 datasetSplitDigest;
        bytes32 inferenceConfigDigest;
        bytes32 randomnessSeedDigest;
        uint32 transcriptSampleCount;
        uint32 transcriptVersion;
        uint256 scoreCommitment;
        uint32 thresholdBps;
        address evaluator;
        bytes32 evaluatorKeyId;
        bytes32 evaluatorPolicyDigest;
        uint32 evaluatorPolicyVersion;
        uint64 claimedAtBlock;
        uint64 claimedAtTime;
        bool revoked;
    }

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
        uint32 thresholdBps,
        address evaluator,
        bytes32 evaluatorPolicyDigest,
        uint32 evaluatorPolicyVersion
    );

    event AttestationRevoked(uint256 indexed attestationId, address indexed actor);
    event EvalClaimRevoked(uint256 indexed attestationId, bytes32 indexed benchmarkDigest, address indexed actor);

    function registerAttestation(
        bytes32 modelFileDigest,
        uint256 weightsRoot,
        bytes32 datasetCommitment,
        bytes32 trainingCommitment,
        bytes32 metadataDigest,
        uint256 parentAttestationId
    ) external returns (uint256 attestationId);

    function registerEvalClaim(
        uint256 attestationId,
        bytes32 benchmarkDigest,
        bytes32 evalTranscriptDigest,
        bytes32 datasetSplitDigest,
        bytes32 inferenceConfigDigest,
        bytes32 randomnessSeedDigest,
        uint32 transcriptSampleCount,
        uint32 transcriptVersion,
        uint256 scoreCommitment,
        uint32 thresholdBps,
        address evaluator,
        bytes32 evaluatorKeyId,
        bytes32 evaluatorPolicyDigest,
        uint32 evaluatorPolicyVersion
    ) external;

    function revokeAttestation(uint256 attestationId) external;

    function revokeEvalClaim(uint256 attestationId, bytes32 benchmarkDigest) external;

    function getAttestation(uint256 attestationId)
        external
        view
        returns (AttestationRecord memory);

    function getEvalClaim(uint256 attestationId, bytes32 benchmarkDigest)
        external
        view
        returns (EvalClaimRecord memory);

    function getOwnerAttestationIds(address owner)
        external
        view
        returns (uint256[] memory);

    function getChildAttestationIds(uint256 attestationId)
        external
        view
        returns (uint256[] memory);

    function getEvalClaimBenchmarkDigests(uint256 attestationId)
        external
        view
        returns (bytes32[] memory);

    function isAttestationActive(uint256 attestationId)
        external
        view
        returns (bool);

    function isEvalClaimActive(uint256 attestationId, bytes32 benchmarkDigest)
        external
        view
        returns (bool);
}
```

### 5.2 Source Revert Rules

`registerAttestation` must revert if:

- `modelFileDigest == 0`
- `weightsRoot == 0`
- `metadataDigest == 0`
- `parentAttestationId != 0` and parent does not exist

`registerEvalClaim` must revert if:

- referenced attestation does not exist
- referenced attestation is revoked
- `benchmarkDigest == 0`
- `evalTranscriptDigest == 0`
- `datasetSplitDigest == 0`
- `inferenceConfigDigest == 0`
- `randomnessSeedDigest == 0`
- `transcriptSampleCount == 0`
- `transcriptVersion == 0`
- `scoreCommitment == 0`
- `thresholdBps > 10000`
- `evaluator == 0`
- `evaluatorKeyId == 0`
- `evaluatorPolicyDigest == 0`
- `evaluatorPolicyVersion == 0`
- an eval claim already exists for the same `(attestationId, benchmarkDigest)` pair

### 5.3 Source Storage Keys

Recommended mappings:

```solidity
mapping(uint256 => AttestationRecord) public attestations;
mapping(uint256 => mapping(bytes32 => EvalClaimRecord)) public evalClaims;
mapping(address => uint256[]) private ownerAttestationIds;
mapping(uint256 => uint256[]) private childAttestationIds;
mapping(uint256 => bytes32[]) private evalClaimBenchmarkDigests;
```

---

## 6. Destination-Chain Contract Interfaces

### 6.1 Shared Proof Types

```solidity
struct Groth16Proof {
    uint256[2] pA;
    uint256[2][2] pB;
    uint256[2] pC;
}
```

### 6.2 `ISemanticVerifier`

```solidity
interface ISemanticVerifier {
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

    event AttestationPackageVerified(
        uint256 indexed sourceChainId,
        address indexed sourceRegistry,
        uint256 indexed attestationId,
        bytes32 adapterId,
        uint32 semanticCircuitVersion
    );

    event AttestationMarkedRevoked(
        uint256 indexed sourceChainId,
        address indexed sourceRegistry,
        uint256 indexed attestationId,
        bytes32 adapterId
    );

    function verifyAttestationPackage(
        bytes calldata packageData
    ) external;

    function isVerified(
        uint256 sourceChainId,
        address sourceRegistry,
        uint256 attestationId
    ) external view returns (bool);

    function getVerifiedAttestation(
        uint256 sourceChainId,
        address sourceRegistry,
        uint256 attestationId
    ) external view returns (VerifiedAttestation memory);
}
```

### 6.3 `IEvalThresholdVerifier`

```solidity
interface IEvalThresholdVerifier {
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

    event EvalClaimPackageVerified(
        uint256 indexed sourceChainId,
        address indexed sourceRegistry,
        uint256 indexed attestationId,
        bytes32 benchmarkDigest,
        bytes32 adapterId,
        uint32 evalCircuitVersion
    );

    event EvalClaimMarkedRevoked(
        uint256 indexed sourceChainId,
        address indexed sourceRegistry,
        uint256 indexed attestationId,
        bytes32 benchmarkDigest,
        bytes32 adapterId
    );

    function verifyEvalClaimPackage(
        bytes calldata packageData
    ) external;

    function isEvalClaimVerified(
        uint256 sourceChainId,
        address sourceRegistry,
        uint256 attestationId,
        bytes32 benchmarkDigest
    ) external view returns (bool);

    function getVerifiedEvalClaim(
        uint256 sourceChainId,
        address sourceRegistry,
        uint256 attestationId,
        bytes32 benchmarkDigest
    ) external view returns (VerifiedEvalClaim memory);
}
```

### 6.4 Destination Verification Order

`verifyAttestationPackage` must:

1. decode package
2. check package version
3. verify committee adapter result
4. verify semantic proof
5. enforce consistency between package fields and proof inputs
6. enforce replay protection
7. store normalized verified record

`verifyEvalClaimPackage` must:

1. decode package
2. check corresponding attestation already verified and not revoked
3. verify committee adapter result
4. verify evaluation proof
5. enforce consistency between package fields and proof inputs
6. enforce replay protection
7. store normalized verified evaluation record

### 6.5 Destination Storage Keys

Recommended keys:

```solidity
bytes32 attestationKey = keccak256(abi.encode(
    sourceChainId,
    sourceRegistry,
    attestationId
));

bytes32 evalClaimKey = keccak256(abi.encode(
    sourceChainId,
    sourceRegistry,
    attestationId,
    benchmarkDigest
));
```

---

## 7. Source Authenticity Adapter Spec

### 7.1 `ISourceAuthAdapter`

```solidity
interface ISourceAuthAdapter {
    function adapterId() external view returns (bytes32);

    function verifySourceRecord(bytes calldata packageData)
        external
        view
        returns (
            bool ok,
            bytes32 sourceRecordHash,
            bytes32 outAdapterId,
            uint256 outSourceChainId,
            uint256 outSourceBlockNumber
        );
}
```

### 7.2 Committee Adapter State

Recommended state:

```solidity
struct CommitteeConfig {
    bytes32 adapterId;
    uint64 activationTime;
    uint32 threshold;
    address[] signers;
    bool active;
}
```

### 7.3 Committee Approval Message

The message signed by committee members must be the EIP-712 typed hash of:

```solidity
struct SourceRecordApproval {
    uint256 sourceChainId;
    address registryAddress;
    uint256 sourceBlockNumber;
    bytes32 sourceBlockHash;
    uint256 attestationId;
    uint8 messageType;
    bytes32 recordContentHash;
    uint256 finalityDelayBlocks;
    bytes32 adapterId;
}
```

Where:

- `recordContentHash` is `sourceRecordHash` for attestation registration and revocation
- `recordContentHash` is `evalClaimRecordHash` for evaluation registration and revocation

### 7.4 Signature Verification Rules

The committee adapter must reject packages when:

- fewer than `threshold` valid signatures are provided
- a signer appears more than once
- any signer is not in the active config
- the package uses an inactive adapter config
- the signed typed hash does not exactly match package content

### 7.5 Recommended Record Hashes

For `ATTESTATION_REGISTER`:

```text
sourceRecordHash = keccak256(abi.encode(
  sourceChainId,
  sourceRegistry,
  attestationId,
  modelFileDigest,
  weightsRoot,
  datasetCommitment,
  trainingCommitment,
  metadataDigest,
  owner,
  parentAttestationId,
  registeredAtBlock,
  false
))
```

For `EVAL_CLAIM_REGISTER`:

```text
evalClaimRecordHash = keccak256(abi.encode(
  sourceChainId,
  sourceRegistry,
  attestationId,
  benchmarkDigest,
  evalTranscriptDigest,
  scoreCommitment,
  thresholdBps,
  evaluatorKeyId,
  claimedAtBlock,
  false
))
```

For revoke messages, include the same primary identifiers plus the revoke flag.

---

## 8. ZK Proof Interfaces

### 8.1 Semantic Proof Public Inputs

The public inputs for `semantic_attestation.circom` `sem-v1` shall be:

```text
[
  attestationId,
  registeredAtBlock,
  weightsRoot,
  attestationCommitment,
  semanticCircuitVersion
]
```

Recommended destination calldata representation:

```solidity
uint256[5] publicSignals
```

### 8.2 Evaluation Proof Public Inputs

The public inputs for `eval_threshold.circom` `eval-v1` shall be:

```text
[
  attestationId,
  field(benchmarkDigest),
  field(evalTranscriptDigest),
  scoreCommitment,
  thresholdBps,
  evalCircuitVersion
]
```

Recommended destination calldata representation:

```solidity
uint256[6] publicSignals
```

### 8.3 Public Input Consistency Checks

The destination verifier must explicitly check:

- `publicSignals[0] == package.attestationId`
- `publicSignals[2] == package.weightsRoot` for semantic packages
- `publicSignals[3] == package.attestationCommitment` for semantic packages
- `publicSignals[1] == field(package.benchmarkDigest)` for eval packages
- `publicSignals[2] == field(package.evalTranscriptDigest)` for eval packages
- `publicSignals[3] == package.scoreCommitment` for eval packages
- `publicSignals[4] == package.thresholdBps` for eval packages

### 8.4 Off-Chain Proof Validation

Before submission, the coordinator should verify proofs off-chain using the same verification key registered on destination chain.

---

## 9. Relay Package Schemas

### 9.1 Encoding Strategy

The on-chain verifier accepts `bytes packageData`.

Off-chain representation uses JSON for transport and debugging, then ABI-encodes the normalized package struct for on-chain submission.

### 9.2 Attestation Relay Package JSON

```json
{
  "package_version": "relay-v1",
  "package_type": "ATTESTATION_REGISTER",
  "source": {
    "source_chain_id": "11155111",
    "source_registry": "0xRegistry",
    "source_block_number": "123456",
    "source_block_hash": "0xBlockHash"
  },
  "attestation": {
    "attestation_id": "42",
    "model_file_digest": "0x...",
    "weights_root": "1234567890",
    "dataset_commitment": "0x...",
    "training_commitment": "0x...",
    "metadata_digest": "0x...",
    "owner": "0xOwner",
    "parent_attestation_id": "0",
    "registered_at_block": "123456",
    "registered_at_time": "1775600000",
    "attestation_commitment": "987654321"
  },
  "adapter": {
    "adapter_id": "0xcommittee-v1",
    "finality_delay_blocks": "12",
    "signatures": [
      {
        "signer": "0xSigner1",
        "signature": "0x..."
      }
    ]
  },
  "proof": {
    "semantic_circuit_version": 1,
    "public_signals": ["42", "123456", "1234567890", "987654321", "1"],
    "groth16": {
      "pA": ["0", "0"],
      "pB": [["0", "0"], ["0", "0"]],
      "pC": ["0", "0"]
    }
  }
}
```

### 9.3 Evaluation Relay Package JSON

```json
{
  "package_version": "relay-v1",
  "package_type": "EVAL_CLAIM_REGISTER",
  "source": {
    "source_chain_id": "11155111",
    "source_registry": "0xRegistry",
    "source_block_number": "123500",
    "source_block_hash": "0xBlockHash"
  },
  "evaluation": {
    "attestation_id": "42",
    "benchmark_digest": "0x...",
    "eval_transcript_digest": "0x...",
    "score_commitment": "4567890123",
    "threshold_bps": 9000,
    "evaluator_key_id": "0x...",
    "claimed_at_block": "123500"
  },
  "adapter": {
    "adapter_id": "0xcommittee-v1",
    "finality_delay_blocks": "12",
    "signatures": [
      {
        "signer": "0xSigner1",
        "signature": "0x..."
      }
    ]
  },
  "proof": {
    "eval_circuit_version": 1,
    "public_signals": ["42", "11", "22", "4567890123", "9000", "1"],
    "groth16": {
      "pA": ["0", "0"],
      "pB": [["0", "0"], ["0", "0"]],
      "pC": ["0", "0"]
    }
  }
}
```

### 9.4 Revocation Relay Package JSON

No ZK proof is required for revocation in MVP. The package contains:

- source identifiers
- revocation message type
- record identifiers
- adapter signatures

### 9.5 ABI Struct Recommendations

Recommended attestation package struct:

```solidity
struct AttestationRelayPackage {
    uint16 packageVersion;
    uint8 packageType;
    uint256 sourceChainId;
    address sourceRegistry;
    uint256 sourceBlockNumber;
    bytes32 sourceBlockHash;
    uint256 attestationId;
    bytes32 modelFileDigest;
    uint256 weightsRoot;
    bytes32 datasetCommitment;
    bytes32 trainingCommitment;
    bytes32 metadataDigest;
    address owner;
    uint256 parentAttestationId;
    uint256 registeredAtBlock;
    uint256 registeredAtTime;
    uint256 attestationCommitment;
    bytes32 adapterId;
    uint256 finalityDelayBlocks;
    address[] signers;
    bytes[] signatures;
    uint32 semanticCircuitVersion;
    Groth16Proof proof;
    uint256[5] publicSignals;
}
```

Recommended eval package struct:

```solidity
struct EvalRelayPackage {
    uint16 packageVersion;
    uint8 packageType;
    uint256 sourceChainId;
    address sourceRegistry;
    uint256 sourceBlockNumber;
    bytes32 sourceBlockHash;
    uint256 attestationId;
    bytes32 benchmarkDigest;
    bytes32 evalTranscriptDigest;
    bytes32 datasetSplitDigest;
    bytes32 inferenceConfigDigest;
    bytes32 randomnessSeedDigest;
    uint32 transcriptSampleCount;
    uint32 transcriptVersion;
    uint256 scoreCommitment;
    uint32 thresholdBps;
    address evaluator;
    bytes32 evaluatorKeyId;
    bytes32 evaluatorPolicyDigest;
    uint32 evaluatorPolicyVersion;
    bytes evaluatorSignature;
    uint256 claimedAtBlock;
    bytes32 adapterId;
    uint256 finalityDelayBlocks;
    address[] signers;
    bytes[] signatures;
    uint32 evalCircuitVersion;
    Groth16Proof proof;
    uint256[6] publicSignals;
}
```

---

## 10. CLI Command Contract

### 10.1 `register-attestation`

Inputs:

- model path
- metadata manifest path
- training manifest path
- dataset manifest path
- source RPC
- source registry address

Outputs:

- source tx hash
- attestation ID
- all computed commitments

Exit behavior:

- non-zero exit if canonicalization fails
- non-zero exit if source transaction reverts

### 10.2 `register-eval-claim`

Inputs:

- attestation ID
- benchmark manifest path
- transcript path
- score commitment
- threshold bps

Outputs:

- source tx hash
- normalized evaluation claim summary

### 10.3 `prove-eval-threshold`

Inputs:

- attestation ID
- benchmark digest
- eval transcript digest
- exact score
- threshold bps
- salt file or generated salt output location
- circuit artifact paths

Outputs:

- score commitment
- proof artifact paths
- public signals

### 10.4 `relay-attestation`

Inputs:

- attestation ID
- source and destination identifiers
- adapter mode

Behavior:

- fetch source record
- wait for finality
- gather signatures
- generate semantic proof if needed
- build relay package
- submit destination transaction

Outputs:

- destination tx hash
- package hash

### 10.5 `query-attestation`

Must return:

- source record summary
- destination verification state
- adapter ID
- semantic circuit version
- revocation status

### 10.6 `export-evidence`

Must export:

- attestation source record
- evaluation source records
- destination verification records
- trust metadata
- referenced digests and content URIs if available

---

## 11. Coordinator API and State

### 11.1 Health API

`GET /health`

Response:

```json
{
  "status": "healthy",
  "source_chain_id": "11155111",
  "last_processed_block": "123520",
  "queue_depth": 4,
  "pending_signature_requests": 1,
  "proof_jobs_in_progress": 1,
  "last_successful_submission": 1775602222,
  "adapter_mode": "committee-v1"
}
```

### 11.2 Optional Package Preview API

`GET /packages/attestation/{sourceChainId}/{registry}/{attestationId}`

Returns:

- fully materialized attestation relay package JSON
- package build status

### 11.3 Coordinator State Tables

Recommended tables:

```sql
CREATE TABLE jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_type TEXT NOT NULL,
    source_chain_id TEXT NOT NULL,
    source_registry TEXT NOT NULL,
    attestation_id TEXT NOT NULL,
    benchmark_digest TEXT,
    source_block_number TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    package_path TEXT,
    dest_tx_hash TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE source_progress (
    source_chain_id TEXT NOT NULL,
    source_registry TEXT NOT NULL,
    last_processed_block TEXT NOT NULL,
    PRIMARY KEY (source_chain_id, source_registry)
);
```

### 11.4 Job States

Valid job states:

- `detected`
- `waiting_finality`
- `collecting_signatures`
- `building_proof`
- `ready_to_submit`
- `submitted`
- `confirmed`
- `failed`

---

## 12. Error Model

### 12.1 Contract Error Categories

Recommended custom errors:

```solidity
error UnsupportedPackageVersion(uint16 version);
error InvalidPackageType(uint8 packageType);
error AdapterVerificationFailed();
error InvalidProof();
error PublicInputMismatch();
error ReplayDetected(bytes32 key);
error AttestationNotVerified();
error AttestationRevoked();
error EvalClaimRevoked();
error InvalidThreshold(uint32 thresholdBps);
error DuplicateSigner(address signer);
error NotEnoughValidSignatures(uint256 provided, uint256 required);
```

### 12.2 CLI Error Categories

- `canonicalization_error`
- `digest_mismatch`
- `proof_generation_error`
- `signature_collection_error`
- `destination_submission_error`
- `query_error`

---

## 13. Event and Replay Semantics

### 13.1 Replay Rules

The same source record may be resubmitted, but the destination contract must treat identical verified state as idempotent.

The contract must reject:

- a conflicting package for the same key with mismatched commitments
- a replay using a stale adapter config if policy forbids it
- a package whose source record has been superseded by revocation

### 13.2 Revocation Ordering

If a revocation package is verified:

- `isVerified` should return `false`
- stored verified record should remain queryable with `revoked = true`
- evaluation claims derived from the revoked attestation should be considered invalid by downstream policy

### 13.3 Event Ordering Assumption

The coordinator may observe events out of order due to RPC behavior. It must reconcile by source block number and log index, not arrival order alone.

---

## 14. Versioning Rules

### 14.1 Protocol Versions

MVP version identifiers:

- package version: `relay-v1`
- field normalization version: `field_norm_v1`
- semantic circuit version: `sem-v1`
- eval circuit version: `eval-v1`
- adapter version: `committee-v1`

### 14.2 Breaking Changes

Any change to:

- public input ordering
- commitment field ordering
- bytes32-to-field mapping
- signed source record shape
- package ABI layout

must produce a new version identifier.

---

## 15. Minimum Test Matrix

### 15.1 Contract Tests

- verify valid attestation package
- reject attestation package with wrong public signals
- reject attestation package with insufficient signatures
- reject duplicate signer usage
- verify valid eval package
- reject eval package when attestation not yet verified
- reject replayed conflicting package
- verify revocation package

### 15.2 Circuit Tests

- semantic proof accepts valid witness
- semantic proof rejects bad Merkle path
- semantic proof rejects altered commitment input
- eval proof accepts valid score and threshold
- eval proof rejects score below threshold
- eval proof rejects wrong score commitment

### 15.3 End-to-End Tests

- register attestation -> collect signatures -> relay -> verify
- register eval claim -> prove threshold -> relay -> verify
- revoke attestation -> relay revoke -> destination shows revoked
- restart coordinator mid-job -> recover and complete
