# Circuit Build

The Groth16 binaries (`*.r1cs`, `*.zkey`, `*_js/*.wasm`, `*.sym`) are gitignored. Use the
build script to regenerate them, the Solidity verifiers, and the test fixtures from source.

For ordinary CI, demo, and proof-generation use, restore the versioned runtime artifacts from
the repository root instead. The fetcher verifies both the archive and individual file hashes:

```bash
python scripts/fetch_proving_artifacts.py
```

## Prerequisites

- Dependencies installed: `npm ci` in `circuits/` (provides `circom2` and `snarkjs`).
- A phase-2 powers-of-tau file `powersOfTau28_hez_final_14_phase2.ptau` present in `circuits/`.
  `2^14` covers both circuits (semantic ≈ 9.2k constraints, eval ≈ 4.3k). Download it once
  from the Hermez/iden3 ptau repository.

## Usage

```bash
cd circuits
npm run build            # rebuild both circuits
npm run build:semantic   # rebuild only the semantic attestation circuit
npm run build:eval       # rebuild only the eval-threshold circuit

# then pick up the regenerated verifiers:
npm run build --prefix ../contracts
```

For each circuit the script compiles the `.circom`, runs the Groth16 setup and a phase-2
contribution, exports the verification key and the Solidity verifier (renaming the contract and
copying it into `contracts/src/generated/`), regenerates the committed test-fixture proof and
public signals, and self-verifies the proof. The eval build also refreshes a FAIL-verdict
fixture (`eval_fail_*.json`) and then runs `scripts/check_eval_constraints.js`, which feeds the
compiled circuit malformed witnesses (negative counts via field wraparound, counts at `2^32`,
empty or out-of-range batches, a sample below `min_sample_count`, a relabelled verdict,
mismatched commitments) and requires each to be rejected by the constraint aimed at it.

## Reproducibility

Groth16 phase-2 contribution mixes fresh entropy, so `.zkey` files and the verifier's
verification-key constants are **not** bit-identical across runs — each run yields a fresh,
valid trusted setup. The fixture *public signals* are witness-determined and stay stable; only
the proof and the VK change. Set `CHAINATTEST_SETUP_ENTROPY` to control the contribution
entropy string. After rebuilding, the regenerated verifier and fixtures are consistent, so the
Hardhat and Python suites pass against them.

The fixture *inputs* (`contracts/test/fixtures/{semantic,eval,eval_fail}_input.json`) are the
source of truth for the witness and are not regenerated here; the build script consumes them
as-is. The eval fixtures carry fixed 254-bit blindings so their commitments are reproducible;
real claims draw fresh blindings in `chain_attest build-eval-input`.
