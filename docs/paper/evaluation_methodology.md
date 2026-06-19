# Evaluation Methodology

## Questions

1. Can ChainAttest prepare and verify attestation and eval packages end to end on a local devnet?
2. What are the bundle-generation and relay latencies?
3. What is the destination-chain gas cost for attestation and eval verification?

## Measurement Sources

- `scripts/run_demo.py`
- `artifacts/demo/demo_summary.json`
- `artifacts/demo/benchmark_summary.md`
- `artifacts/demo-fabric-paper/demo_summary.json`
- `artifacts/demo-fabric-paper/benchmark_summary.md`
- Hardhat-based contract tests in `contracts/test/`
- Fabric-to-public relay and revocation coverage in `tests/test_destination_submission.py`

## Primary Metrics

- attestation bundle generation time
- attestation relay latency
- eval bundle generation time
- eval relay latency
- attestation gas used
- eval gas used
- Fabric-to-public path properties such as explicit `sourceSystemId`, `sourceChannelId`, and `sourceTxId`

## Notes

- these numbers are local-devnet measurements, not production benchmarks
- proof times depend on the current Groth16 artifacts and machine characteristics
- the benchmark is intended for reproducibility and paper/demo packaging rather than final performance claims
- the Fabric-specific paper snapshot is summarized in `docs/paper/fabric_public_evaluation.md`
