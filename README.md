# ChainAttest

ChainAttest is a research-first protocol and reference implementation for carrying machine-learning attestations across chains as typed evidence rather than as assets.

The project focuses on a specific cross-chain problem that ordinary bridges do not solve well: proving and transporting structured AI provenance and evaluation claims such as model identity, dataset commitments, training commitments, and thresholded evaluation results. The implementation combines committee-authenticated source records, ML-specific Groth16 proofs, evaluator statements, and a Python orchestration layer that can build, sign, submit, recover, and benchmark the full flow end to end.

## What This Repository Demonstrates

Today’s prototype is not just a paper scaffold. The repository includes a working EVM-to-EVM pipeline that can:

- register and track source-side model attestations and evaluation claims
- generate semantic and evaluation proofs from Circom circuits and Groth16 artifacts
- assemble typed relay packages for attestation and eval claims
- collect committee approvals and evaluator signatures
- verify those packages on destination contracts
- submit them automatically through a coordinator
- recover persisted jobs after restart
- benchmark and package the whole flow into demo artifacts

## Core Thesis

ChainAttest is built around five claims:

1. The payload is attestation evidence, not assets.
2. The proof relations are ML-specific, not just consensus- or transfer-specific.
3. Evaluation claims can be privacy-preserving instead of exposing the raw score.
4. Cross-chain verification should separate source authenticity from semantic verification.
5. The resulting destination record can serve as public compliance evidence for provenance and traceability workflows.

## Architecture

The current design is easiest to understand as four layers.

### 1. Source-Side Semantics

`contracts/src/ModelRegistry.sol` records structured model attestations and evaluation claims, including:

- model lineage
- ownership
- revocation-aware status
- structured evaluation transcript summaries with batch-aware result digests

### 2. Source Authenticity

`CommitteeAuthAdapter` verifies committee approvals over typed source-record packages after a configured finality window. This keeps source-authenticity logic separate from proof semantics.

### 3. Destination Semantic Verification

The destination verifier stack checks:

- committee-authenticated attestation packages
- semantic Groth16 proofs for ML attestation integrity
- evaluation Groth16 proofs for thresholded private claims
- evaluator authorization and evaluator-policy metadata
- structured transcript consistency, including batch summary digests and derived score checks
- replay protection and public-signal consistency
- normalized permissioned-source identities via `sourceSystemId`, `sourceChannelId`, `sourceTxId`, and deterministic synthetic registry addresses

### 4. Operational Orchestration

The coordinator prepares bundles, generates proofs, collects signatures, submits packages, persists job state to SQLite, and recovers pending work after restart. The preferred signer boundary is now a local HTTP signer service with bearer-token auth, nonce and timestamp checks, JSON policy controls, and signer-side audit logging.

## Current Feature Set

### Contracts and Proofs

- Solidity contracts for source registration, semantic verification, evaluation verification, and committee authentication
- generated Groth16 verifier contracts in `contracts/src/generated/`
- real proof fixtures used by the Hardhat integration tests
- Circom circuits for semantic attestation and batch-aware evaluation-threshold proofs

### Coordinator and CLI

- CLI commands for manifest creation, witness preparation, and package rendering
- proof generation through `snarkjs`
- committee approval collection
- evaluator signature collection
- destination transaction submission
- persisted restart recovery and retry scheduling
- SQLite-backed job and audit storage with migration from legacy JSON artifacts

### Signer Boundary

- preferred HTTP signer service in `committee/signer_service/http_service.py`
- command-backed signer host in `committee/signer_service/host.py` as a fallback/debug path
- bearer-token auth for the HTTP service
- request timestamp and nonce enforcement with replay-window checks
- signer policy loaded from JSON
- signer-side audit logging

### Demo and Benchmark Packaging

- one-command local demo runner in `scripts/run_demo.py`
- artifact bundle generation under `artifacts/demo/`
- machine-readable benchmark summary
- markdown benchmark table
- demo runbook and paper-support docs under `docs/`
- heterogeneous source support for Fabric-style permissioned registries through committee-authenticated `sourceSystemId` packages with explicit channel and transaction IDs

## Repository Map

| Path | Purpose |
| --- | --- |
| `SRS_ChainAttest_Revised.md` | Revised SRS and research framing |
| `ChainAttest_Protocol_and_Interface_Spec.md` | Protocol, package, and interface specification |
| `contracts/` | Solidity contracts, generated verifiers, and Hardhat tests |
| `circuits/` | Circom circuits and proving artifacts |
| `cli/` | Python CLI for manifests, witness inputs, and package rendering |
| `coordinator/` | Coordinator service, SQLite storage, audit helpers, and operator commands |
| `committee/` | HTTP signer service, command fallback host, and signer clients |
| `schemas/` | JSON schemas for structured attestation and eval inputs |
| `tests/` | Python orchestration, persistence, signer-boundary, and operator tests |
| `docs/demo/` | Demo runbook, expected outputs, and troubleshooting |
| `docs/paper/` | Thesis framing, evaluation notes, related-work outline, and threat model |
| `docs/figures/` | Source-controlled Mermaid figure files |
| `scripts/run_demo.py` | Reproducible local demo and benchmark runner |

## Runtime Baseline

The repository is pinned to:

- Node.js `24.15.0`
- npm `11.12.1`
- Python `3.11+`

The repo includes `.nvmrc`, `.node-version`, and root `.npmrc` with `engine-strict=true`.

## Quick Start

### 1. Install Dependencies

```bash
nvm use
npm ci --prefix contracts
npm ci --prefix circuits
python -m pip install -e ./cli
```

### 2. Validate The Main Paths

```bash
cd contracts
npm run build
npm test
cd ..

python -m unittest discover -s tests
python -m compileall cli coordinator committee tests scripts
python coordinator/chainattest_coordinator/ops.py --help
```

### 3. Run The Local Demo

```bash
python scripts/run_demo.py --output-root artifacts/demo
python scripts/run_demo.py --source-mode fabric --output-root artifacts/demo-fabric
```

The demo will:

- start or reuse a Hardhat node
- start or reuse the HTTP signer service
- deploy the destination fixture
- prepare and submit an attestation package
- prepare and submit an eval package
- confirm destination verification
- write benchmark and artifact outputs under `artifacts/demo/`

In `fabric` mode, the demo additionally emits:

- a nonzero `sourceSystemId`
- explicit `sourceChannelId`
- explicit `sourceTxId`
- a deterministic synthetic `sourceRegistry` derived from `sourceSystemId`

## Demo Outputs

After a successful run, the most important files are:

- `artifacts/demo/demo_summary.json`
- `artifacts/demo/benchmark_summary.md`
- `artifacts/demo/attestation/attestation_package.json`
- `artifacts/demo/eval/eval_package.json`
- `artifacts/demo/state/chainattest.db`
- `artifacts/demo/state/audit.jsonl`
- `artifacts/demo/signer-audit.jsonl`

## Operator Workflows

The operator CLI is database-first now.

Examples:

```bash
python coordinator/chainattest_coordinator/ops.py health --db-path coordinator/state/chainattest.db
python coordinator/chainattest_coordinator/ops.py list-jobs --db-path coordinator/state/chainattest.db
python coordinator/chainattest_coordinator/ops.py show-job <job-id> --db-path coordinator/state/chainattest.db
python coordinator/chainattest_coordinator/ops.py resume --db-path coordinator/state/chainattest.db
python coordinator/chainattest_coordinator/ops.py retry-failed --db-path coordinator/state/chainattest.db
python coordinator/chainattest_coordinator/ops.py tail-audit --db-path coordinator/state/chainattest.db --limit 25
```

Legacy JSON state and JSONL audit files are still written as compatibility shadows, but SQLite is the authoritative store.

## Signer Modes

### Preferred Mode: HTTP Signer Service

The preferred boundary is `committee/signer_service/http_service.py`.

It provides:

- `GET /health`
- `POST /approve`
- `POST /sign-eval`
- `POST /submit`

And enforces:

- bearer-token auth
- timestamp and nonce headers
- replay-window checks
- JSON policy allowlists
- signer-side audit logging

### Fallback Mode: Command Host

`committee/signer_service/host.py` remains available as a fallback/debug boundary for local command-backed signing and submission.

## CI

GitHub Actions currently covers:

- contract build and test
- Python orchestration and recovery tests
- operator CLI checks
- a workflow-dispatch demo smoke run that uploads demo artifacts

## Demo And Paper Support Docs

### Demo Docs

- `docs/demo/runbook.md`
- `docs/demo/expected_outputs.md`
- `docs/demo/troubleshooting.md`

### Paper Docs

- `docs/paper/contributions_and_thesis.md`
- `docs/paper/evaluation_methodology.md`
- `docs/paper/related_work_outline.md`
- `docs/paper/threat_model.md`

### Figure Sources

- `docs/figures/architecture.mmd`
- `docs/figures/demo_flow.mmd`

## Known Prototype Limits

This is a high-credibility research prototype, not a production launch.

Important current limits:

- the eval proof is bound to a batch-aware structured transcript summary, not a fully proved benchmark execution trace
- the HTTP signer service is still a local reference boundary, not an HSM or managed secret platform
- SQLite provides strong single-host durability, not multi-writer distributed coordination
- the current permissioned-source path is committee-authenticated and normalized through synthetic registry addresses plus explicit channel / transaction IDs, not a native Hyperledger Fabric light-client integration

## Suggested Next Steps

The strongest next engineering moves are:

1. move from batch-aware transcript summaries toward signed or provable evaluator execution traces
2. replace the local signer reference service with a stronger isolated signer or secret-manager-backed boundary
3. extend durability and observability for multi-worker coordination
4. expand benchmark depth and paper-facing evaluation outputs

## Primary Documents

- [SRS_ChainAttest_Revised.md](SRS_ChainAttest_Revised.md)
- [ChainAttest_Protocol_and_Interface_Spec.md](ChainAttest_Protocol_and_Interface_Spec.md)
