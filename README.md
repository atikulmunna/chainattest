# ChainAttest

ChainAttest is a research-oriented protocol and reference implementation for cross-chain machine learning attestations.

The system is designed for cases where the payload is not an asset transfer, but structured ML evidence: model provenance, training commitments, deployment metadata, and privacy-preserving evaluation claims. ChainAttest combines source-authenticity checks, typed relay packages, and zero-knowledge verification so that attestations created on one chain can be verified and consumed on another.

## Core Ideas

- Typed ML attestations instead of token transfers or generic message passing
- Semantic verification over ML-specific commitments such as model, dataset, and training metadata
- Privacy-preserving evaluation threshold proofs
- Explicit evaluator attestations for evaluation claims
- A path toward public compliance evidence for AI provenance and auditability

## Repository Contents

- `SRS_ChainAttest_Revised.md`
  Revised system requirements specification and research framing
- `ChainAttest_Protocol_and_Interface_Spec.md`
  Builder-facing protocol, interface, and package format specification
- `contracts/`
  Solidity contracts, generated Groth16 verifiers, and Hardhat test suite
- `circuits/`
  Circom circuits, proving artifacts, and verifier exports
- `cli/`
  Python CLI for attestation and eval manifests, witness inputs, and relay package generation
- `coordinator/`
  Python coordinator service with persistent job tracking, proof generation, signature orchestration, and destination submission helpers
- `committee/`
  Local committee signer service for typed approval collection
- `schemas/`
  JSON schemas for attestation and evaluation claim payloads

## Current Implementation Status

The repository currently includes:

- a source-side model registry with lineage, ownership lookup, structured eval claim storage, and revocation-aware activity checks
- committee-backed source record authentication
- semantic attestation verification with generated Groth16 verifier contracts
- evaluation threshold verification with generated Groth16 verifier contracts
- evaluator EIP-712 attestations for evaluation claims
- structured transcript commitments and evaluator policy metadata checks for eval claims
- a working CLI flow for manifest generation, witness preparation, and relay package rendering
- a coordinator helper that orchestrates CLI-based manifest building, Groth16 proof generation, evaluator signing, and committee approval collection
- destination-chain submission helpers with resumable submission jobs backed by persisted coordinator state
- GitHub Actions CI for contract build/test and Python CLI/coordinator checks
- Python orchestration tests covering generated proofs, signed relay bundles, destination submission, and recovery after restart
- end-to-end relay tests covering valid flows, replay rejection, signature failures, public input mismatches, and invalid proofs

## Architecture Summary

For attestation verification:

1. A source-side record is committed by a registry.
2. A committee signs the source record hash after the configured finality delay.
3. A relay package carries the typed record plus a semantic proof.
4. The destination verifier checks source authenticity, package/proof consistency, and the semantic proof.

For evaluation claim verification:

1. A verified attestation acts as the parent identity.
2. An evaluator signs a typed evaluation statement.
3. A relay package carries structured transcript metadata, an evaluation proof, and committee approvals.
4. The destination verifier checks committee approval, evaluator authorization, transcript commitment consistency, and the evaluation proof.

## Quick Start

```bash
cd contracts
npm install
npm run build
npm test
```

## Project Layout

```text
contracts/    Solidity contracts and contract tests
circuits/     Circom circuits and proving artifacts
cli/          Python CLI for manifests, witness inputs, and relay packages
coordinator/  Python coordinator with proof, signature, persistence, and submission helpers
committee/    Local typed-data committee signer service
schemas/      JSON schemas for source records
benchmarks/   Benchmark-related workspace
docs/         Supplemental docs
```

## Near-Term Priorities

1. Add richer transcript summaries beyond metadata-only transcript commitments.
2. Add richer persistent coordinator state, retries, and safe secret-management boundaries beyond local prototype storage.
3. Expand deployment automation and CI coverage for circuit regeneration, proving artifacts, and integration flows.
4. Add source-to-destination integration scripts and operator tooling that connect the registry, CLI, coordinator, and verifier contracts.
