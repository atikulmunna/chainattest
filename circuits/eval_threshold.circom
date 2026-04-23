pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

template EvalThresholdV1() {
    signal input attestation_id;
    signal input benchmark_digest_field;
    signal input eval_transcript_digest_field;
    signal input score_commitment;
    signal input threshold_bps;
    signal input circuit_version_id;

    signal input exact_score;
    signal input salt;
    signal input transcript_sample_count;
    signal input correct_count;
    signal input incorrect_count;
    signal input abstain_count;

    // Bind the private score to the attestation and benchmark context so the proof
    // cannot be replayed as a generic threshold statement.
    component scoreHasher = Poseidon(5);
    scoreHasher.inputs[0] <== attestation_id;
    scoreHasher.inputs[1] <== benchmark_digest_field;
    scoreHasher.inputs[2] <== eval_transcript_digest_field;
    scoreHasher.inputs[3] <== exact_score;
    scoreHasher.inputs[4] <== salt;
    scoreHasher.out === score_commitment;

    component gte = GreaterEqThan(14);
    gte.in[0] <== exact_score;
    gte.in[1] <== threshold_bps;
    gte.out === 1;

    component lte = LessEqThan(14);
    lte.in[0] <== exact_score;
    lte.in[1] <== 10000;
    lte.out === 1;

    correct_count + incorrect_count + abstain_count === transcript_sample_count;
    exact_score * transcript_sample_count === correct_count * 10000;

    circuit_version_id === 2;
}

component main {public [
    attestation_id,
    benchmark_digest_field,
    eval_transcript_digest_field,
    score_commitment,
    threshold_bps,
    circuit_version_id
]} = EvalThresholdV1();
