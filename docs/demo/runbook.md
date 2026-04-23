# ChainAttest Demo Runbook

## Goal

Run a complete local ChainAttest flow that:

1. starts or reuses a Hardhat node
2. starts or reuses the HTTP signer service
3. deploys the destination verifier fixture
4. prepares and submits an attestation package
5. prepares and submits an eval package
6. verifies both packages on the destination chain
7. writes benchmark and artifact outputs under `artifacts/demo/`

## Command

```bash
python scripts/run_demo.py --output-root artifacts/demo
```

## Optional Reuse Flags

```bash
python scripts/run_demo.py \
  --output-root artifacts/demo \
  --rpc-url http://127.0.0.1:8545 \
  --signer-url http://127.0.0.1:8787
```

## What The Demo Produces

- sample source inputs under `artifacts/demo/samples/`
- attestation bundle artifacts under `artifacts/demo/attestation/`
- eval bundle artifacts under `artifacts/demo/eval/`
- coordinator state and SQLite DB under `artifacts/demo/state/`
- signer audit log under `artifacts/demo/signer-audit.jsonl`
- machine-readable summary in `artifacts/demo/demo_summary.json`
- markdown benchmark table in `artifacts/demo/benchmark_summary.md`

## Success Criteria

- the script exits with code `0`
- `demo_summary.json` reports `verified: true` for both attestation and eval
- benchmark output includes bundle times, relay times, and gas usage
- coordinator and signer audit artifacts are present
