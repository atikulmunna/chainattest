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
  Python CLI scaffold
- `coordinator/`
  Coordinator service scaffold
- `committee/`
  Committee signer service scaffold
- `schemas/`
  JSON schemas for attestation and evaluation claim payloads

## Current Implementation Status

The repository currently includes:

- committee-backed source record authentication
- semantic attestation verification with generated Groth16 verifier contracts
- evaluation threshold verification with generated Groth16 verifier contracts
- evaluator EIP-712 attestations for evaluation claims
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
cli/          Python CLI scaffold
coordinator/  Python coordinator scaffold
committee/    Committee signer service scaffold
schemas/      JSON schemas for source records
benchmarks/   Benchmark-related workspace
docs/         Supplemental docs
```

## Near-Term Priorities

1. Implement persistent source-chain model registry behavior in `ModelRegistry.sol`.
2. Expand structured transcript commitments and evaluator policy semantics.
3. Add witness-generation helpers and packaging scripts for `sem-v1` and `eval-v1`.
4. Add deployment automation and CI for the contract and circuit toolchains.
