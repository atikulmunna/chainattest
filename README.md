# ChainAttest

ChainAttest is a cross-chain attestation system for machine learning provenance, deployment evidence, and privacy-preserving evaluation claims.

Instead of moving assets, ChainAttest relays typed ML attestations across chains and verifies two distinct proof layers:

- source authenticity through a committee-backed relay package
- semantic attestation integrity through Groth16 proofs over ML-specific commitments
- private evaluation threshold claims through Groth16 proofs bound to benchmark and transcript context

## What Is In This Repository

- `SRS_ChainAttest_Revised.md`: revised system requirements specification
- `ChainAttest_Protocol_and_Interface_Spec.md`: protocol and interface details for implementation
- `contracts/`: Solidity contracts, generated verifiers, and Hardhat tests
- `circuits/`: Circom circuits, proving artifacts, and verifier exports
- `cli/`: Python CLI scaffold
- `coordinator/`: coordinator service scaffold
- `committee/`: signer service scaffold
- `schemas/`: JSON schemas for attestation and evaluation claim payloads

## Current Status

- committee signature verification and typed relay package decoding are implemented
- semantic and eval proof paths are wired to real generated Groth16 verifier contracts
- end-to-end Hardhat tests cover valid relay flows, replay rejection, public input mismatch rejection, and invalid proof rejection

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

## Next Steps

1. Implement persistent source-chain model registry behavior in `ModelRegistry.sol`.
2. Add transcript-structure or evaluator-attestation semantics to the eval proof model.
3. Build witness-generation helpers and packaging scripts for `sem-v1` and `eval-v1`.
4. Add deployment scripts and CI for the contracts and circuit toolchain.
