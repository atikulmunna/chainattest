# ChainAttest

ChainAttest is a research-oriented protocol and reference implementation for cross-chain machine learning attestations.

Instead of moving assets, ChainAttest moves structured AI evidence: model identity, dataset and training commitments, deployment metadata, and privacy-preserving evaluation claims. The project combines typed relay packages, threshold committee attestations, evaluator statements, and zero-knowledge verification so an attestation created on one chain can be verified and consumed on another without turning the destination verifier into a blind trust sink.

## Why This Project Exists

Most bridge designs are built for token transfers or generic message passing. ChainAttest targets a different payload and a different trust question:

- the payload is typed ML provenance and evaluation evidence, not fungible assets
- the proof semantics are ML-specific, not just consensus or message delivery semantics
- evaluation quality can be attested privately instead of exposing raw scores, datasets, or weights
- the resulting record can support public auditability and compliance-evidence workflows for AI systems

That makes ChainAttest useful for cases such as:

- anchoring a model registration event from a source chain to a destination verifier
- proving that a model met a benchmark threshold without publishing the exact score
- carrying evaluator-approved, policy-bound evaluation claims across domains
- building public evidence trails for provenance, deployment authorization, and traceability

## Design Summary

ChainAttest currently separates the problem into three layers:

1. Source authenticity
   Committee signers attest to a typed source record after a configured finality delay.
2. Semantic verification
   Groth16 proofs verify ML-specific attestation or evaluation relations on the destination chain.
3. Operational orchestration
   A Python coordinator prepares artifacts, generates proofs, collects signatures, submits destination transactions, and recovers persisted jobs after restart.

### Attestation Flow

1. A source-side registry records a model attestation.
2. The coordinator waits for the required finality window.
3. A committee signs the typed attestation package.
4. A semantic Groth16 proof binds the attestation metadata to the committed weights root.
5. The destination verifier checks the package, committee approvals, and proof.

### Evaluation Flow

1. A verified attestation acts as the parent identity.
2. The evaluator signs a typed statement over the benchmark and transcript context.
3. A structured transcript digest is derived from benchmark, split, inference, randomness, and sample-count fields.
4. A Groth16 proof shows the hidden score meets the declared threshold while staying bound to the attestation and transcript context.
5. The destination verifier checks committee approvals, evaluator authorization, transcript consistency, and the proof.

## Current Repository Status

This repository is no longer only a paper scaffold. The current prototype includes:

- Solidity contracts for source registration, semantic verification, evaluation verification, and committee authentication
- generated Groth16 verifier contracts and real proof fixtures
- Circom circuits for semantic attestation and evaluation-threshold proofs
- a Python CLI for manifest creation, witness preparation, and relay package rendering
- a coordinator service that prepares bundles, generates proofs, collects signatures, submits packages, and resumes jobs after restart
- command-backed signer and submitter boundaries so signing and submission can be delegated outside the coordinator process
- signer-host authentication and policy checks
- coordinator and signer audit logs
- retryable submission failures with backoff
- atomic coordinator state persistence and persisted restart recovery
- operator commands for inspecting jobs and audit history
- GitHub Actions validation for contracts, Python tooling, and operator entrypoints

## Repository Structure

| Path | Purpose |
| --- | --- |
| `SRS_ChainAttest_Revised.md` | Revised system requirements and research framing |
| `ChainAttest_Protocol_and_Interface_Spec.md` | Builder-facing protocol, interface, and package specification |
| `contracts/` | Solidity contracts, generated verifiers, deployment helpers, and Hardhat tests |
| `circuits/` | Circom circuits, proving artifacts, and verifier-generation inputs |
| `cli/` | Python CLI for manifests, witness inputs, and relay package rendering |
| `coordinator/` | Coordinator service, audit utilities, persistence helpers, and operator commands |
| `committee/` | Committee and evaluator signing helpers plus a local signer-host boundary |
| `schemas/` | JSON schemas for structured attestation and evaluation inputs |
| `tests/` | Python orchestration, recovery, and operator-tooling tests |

## Implemented Capabilities

### Destination Verification

- committee-backed source package authentication
- semantic attestation verification with generated Groth16 verifier integration
- evaluation-threshold verification with generated Groth16 verifier integration
- replay protection and public-input consistency checks
- evaluator authorization and EIP-712 evaluator statements
- structured transcript digest enforcement
- evaluator policy digest and policy-version checks

### Coordinator Orchestration

- attestation and evaluation bundle preparation
- witness generation and `snarkjs` proof generation
- committee-signature collection
- evaluator-signature collection
- destination transaction submission
- persisted job state and restart recovery
- retry scheduling for retryable submission failures
- atomic state snapshots and append-only audit logging

### Operational Hardening

- secret references instead of persisting raw submitter keys
- environment-backed and in-memory secret reference handling
- external command-backed signing and submission boundaries
- signer-host authentication tokens
- signer-host policy allowlists for actions, verifiers, package kinds, and destination chains
- separate coordinator and signer audit logs
- local operator commands for job inspection, retry, resume, and audit tailing

## Quick Start

### Contracts

```bash
cd contracts
npm install
npm run build
npm test
```

### Python Tooling

```bash
python -m compileall cli coordinator committee tests
python cli/chain_attest/main.py --help
python coordinator/chainattest_coordinator/ops.py --help
python -m unittest discover -s tests
```

## Operator Commands

The operator CLI is available at `coordinator/chainattest_coordinator/ops.py`.

Common commands:

```bash
python coordinator/chainattest_coordinator/ops.py health --state-path coordinator/state/jobs.json
python coordinator/chainattest_coordinator/ops.py list-jobs --state-path coordinator/state/jobs.json
python coordinator/chainattest_coordinator/ops.py show-job <job-id> --state-path coordinator/state/jobs.json
python coordinator/chainattest_coordinator/ops.py resume --state-path coordinator/state/jobs.json
python coordinator/chainattest_coordinator/ops.py retry-failed --state-path coordinator/state/jobs.json
python coordinator/chainattest_coordinator/ops.py tail-audit --audit-log-path coordinator/state/audit.jsonl --limit 25
```

## Signer Boundary

The reference signer host is a local command-backed boundary in `committee/signer_service/host.py`.

It currently supports:

- committee approval signing
- evaluator statement signing
- destination-package submission
- optional auth token enforcement
- optional policy allowlists
- signer-side audit logging

Environment variables recognized by the signer host include:

- `CHAINATTEST_SIGNER_AUTH_TOKEN`
- `CHAINATTEST_SIGNER_ALLOWED_ACTIONS`
- `CHAINATTEST_SIGNER_ALLOWED_VERIFIERS`
- `CHAINATTEST_SIGNER_ALLOWED_PACKAGE_KINDS`
- `CHAINATTEST_SIGNER_ALLOWED_DESTINATION_CHAINS`
- `CHAINATTEST_SIGNER_AUDIT_LOG`

## Persistence and Recovery

The coordinator persists job state to `coordinator/state/jobs.json` by default and writes an append-only audit trail to `coordinator/state/audit.jsonl`.

The current persistence model provides:

- restart recovery for prepared, submitted, and retryable failed jobs
- atomic state-file replacement
- locked audit-log appends
- retry metadata such as error kind, retryability, next retry time, and attempt count

This is good enough for a single-host research prototype, but it is not yet a distributed queue or multi-worker control plane.

## Validation

The repository currently validates through:

- Hardhat contract build and test runs
- Python orchestration and recovery tests
- operator CLI tests
- GitHub Actions checks for contracts and Python tooling

At the time of the latest local validation, the following commands were expected to pass:

```bash
cd contracts && npm run build && npm test
python -m unittest discover -s tests
python -m compileall cli coordinator committee tests
```

## Known Prototype Limits

ChainAttest is already useful as a serious research prototype, but some boundaries are still intentionally unfinished:

- the evaluator proof is bound to a structured transcript digest, not a fully proved benchmark execution trace
- the command-backed signer host is a local reference boundary, not a production HSM or managed secret service
- coordinator persistence is durable for single-host recovery, not yet designed for multi-writer coordination
- the broader deployment story still needs packaging, infrastructure automation, and production-grade service boundaries

## Near-Term Priorities

The highest-value next improvements are:

1. make evaluator transcript semantics richer than the current metadata-level commitment
2. replace the local signer host with a stronger isolated signer or secret-manager-backed boundary
3. move coordinator durability from single-host JSON persistence toward a real operational datastore
4. expand deployment and integration automation around proving artifacts, submission flows, and operator recovery

## Primary Documents

- [SRS_ChainAttest_Revised.md](SRS_ChainAttest_Revised.md)
- [ChainAttest_Protocol_and_Interface_Spec.md](ChainAttest_Protocol_and_Interface_Spec.md)

These two files are the best entry points if you want the research framing and the builder-facing protocol details side by side.
