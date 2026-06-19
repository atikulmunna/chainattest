# Fabric-To-Public Evaluation Snapshot

## Scenario

This snapshot evaluates the differentiated ChainAttest path where a permissioned Fabric-style source emits attestation and evaluation records that are verified on a public-style Ethereum destination.

The run used:

- nonzero `sourceSystemId`
- explicit `sourceChannelId`
- explicit `sourceTxId`
- `FabricCommitteeAuthAdapter`
- committee-authenticated relay packages
- destination-side semantic and eval verification

## Benchmark Source

- command: `python scripts/run_demo.py --source-mode fabric --output-root artifacts/demo-fabric-paper`
- machine-readable output: `artifacts/demo-fabric-paper/demo_summary.json`
- markdown output: `artifacts/demo-fabric-paper/benchmark_summary.md`

## Table 1. Fabric-To-Public Benchmark Snapshot

| Metric | Value |
| --- | --- |
| Attestation bundle time (s) | 2.219 |
| Attestation relay time (s) | 1.577 |
| Eval bundle time (s) | 4.472 |
| Eval relay time (s) | 1.545 |
| Attestation gas used | 567040 |
| Eval gas used | 669803 |

## Table 2. Fabric-To-Public Path Properties

| Property | Observed value |
| --- | --- |
| Source mode | `fabric` |
| Destination chain id | `31337` |
| Permissioned source chain id used in package | `424242` |
| Nonzero `sourceSystemId` present | yes |
| Explicit `sourceChannelId` present | yes |
| Explicit `sourceTxId` present | yes |
| Synthetic normalized `sourceRegistry` used | yes |
| Committee threshold in demo fixture | `2` |
| Attestation verified on destination | `true` |
| Eval claim verified on destination | `true` |
| End-to-end revocation path implemented | yes |
| End-to-end revocation path validated | `tests/test_destination_submission.py` |

## Interpretation

The Fabric-to-public route is not just a framing claim in the paper. The current prototype demonstrates that permissioned-source identifiers survive package construction, committee authentication, destination verification, and downstream auditability without collapsing back into a plain EVM-only provenance model.

The benchmark numbers are local-devnet measurements, so they should be treated as reproducibility evidence rather than production performance claims. Their purpose is to show that the heterogeneous path is executable, measurable, and stable enough to support an academic demo and paper artifact.
