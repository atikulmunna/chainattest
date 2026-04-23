# Threat Model And Trust Assumptions

## Trusted Or Semi-Trusted Components

- committee signers are trusted to attest to source-chain records after the chosen finality window
- authorized evaluators are trusted to stand behind the structured transcript summary they sign
- the destination chain is trusted to execute verifier contracts correctly

## Adversarial Goals Considered

- forging committee approvals
- replaying previously accepted source records
- presenting mismatched public inputs to the verifier
- submitting evaluator claims with mismatched transcript structure
- using stale or replayed signer-service requests

## Out Of Scope

- fully proving benchmark execution traces
- production HSM or managed secret-service guarantees
- multi-writer distributed coordinator consensus

## Residual Risk

The eval path proves a thresholded claim over a structured transcript summary, not the full benchmark execution. This is a strong research-prototype position, but not a complete elimination of evaluator trust.
