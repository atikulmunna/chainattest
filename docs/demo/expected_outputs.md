# Demo Expected Outputs

## Summary File

`artifacts/demo/demo_summary.json` should contain:

- deployed fixture addresses
- attestation bundle and submission results
- eval bundle and submission results
- destination verification booleans
- benchmark timings
- artifact paths

## Benchmark Table

`artifacts/demo/benchmark_summary.md` should contain:

- attestation bundle time
- attestation relay time
- eval bundle time
- eval relay time
- attestation gas used
- eval gas used

## Coordinator Artifacts

- `artifacts/demo/state/jobs.json`
- `artifacts/demo/state/audit.jsonl`
- `artifacts/demo/state/chainattest.db`

## Signer Artifacts

- `artifacts/demo/signer-audit.jsonl`
- `artifacts/demo/signer-policy.json`

## Bundle Artifacts

### Attestation

- `attestation_manifest.json`
- `semantic_input.json`
- `semantic_proof.json`
- `semantic_public.json`
- `committee_signatures.json`
- `attestation_package.json`

### Eval

- `eval_claim_manifest.json`
- `eval_input.json`
- `eval_proof.json`
- `eval_public.json`
- `committee_signatures.json`
- `eval_package.json`
