pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

template EvalThresholdV2() {
    signal input attestation_id;
    signal input benchmark_digest_field;
    signal input eval_transcript_digest_field;
    signal input batch_results_digest_field;
    signal input score_commitment;
    signal input threshold_bps;
    signal input circuit_version_id;

    signal input exact_score;
    signal input salt;
    signal input transcript_sample_count;
    signal input correct_count;
    signal input incorrect_count;
    signal input abstain_count;
    signal input batch_count;
    signal input batch_correct_counts[4];
    signal input batch_incorrect_counts[4];
    signal input batch_abstain_counts[4];

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

    component batchCountLte = LessEqThan(4);
    batchCountLte.in[0] <== batch_count;
    batchCountLte.in[1] <== 4;
    batchCountLte.out === 1;

    correct_count + incorrect_count + abstain_count === transcript_sample_count;
    exact_score * transcript_sample_count === correct_count * 10000;

    signal total_batch_correct[5];
    signal total_batch_incorrect[5];
    signal total_batch_abstain[5];
    total_batch_correct[0] <== 0;
    total_batch_incorrect[0] <== 0;
    total_batch_abstain[0] <== 0;

    component seedHasher = Poseidon(5);
    seedHasher.inputs[0] <== batch_count;
    seedHasher.inputs[1] <== 0;
    seedHasher.inputs[2] <== 0;
    seedHasher.inputs[3] <== 0;
    seedHasher.inputs[4] <== 0;

    signal batch_hash[5];
    component stepHasher[4];
    batch_hash[0] <== seedHasher.out;

    for (var i = 0; i < 4; i++) {
        total_batch_correct[i + 1] <== total_batch_correct[i] + batch_correct_counts[i];
        total_batch_incorrect[i + 1] <== total_batch_incorrect[i] + batch_incorrect_counts[i];
        total_batch_abstain[i + 1] <== total_batch_abstain[i] + batch_abstain_counts[i];

        stepHasher[i] = Poseidon(5);
        stepHasher[i].inputs[0] <== batch_hash[i];
        stepHasher[i].inputs[1] <== batch_correct_counts[i];
        stepHasher[i].inputs[2] <== batch_incorrect_counts[i];
        stepHasher[i].inputs[3] <== batch_abstain_counts[i];
        stepHasher[i].inputs[4] <== i + 1;
        batch_hash[i + 1] <== stepHasher[i].out;
    }

    total_batch_correct[4] === correct_count;
    total_batch_incorrect[4] === incorrect_count;
    total_batch_abstain[4] === abstain_count;
    batch_hash[4] === batch_results_digest_field;

    circuit_version_id === 3;
}

component main {public [
    attestation_id,
    benchmark_digest_field,
    eval_transcript_digest_field,
    batch_results_digest_field,
    score_commitment,
    threshold_bps,
    circuit_version_id
]} = EvalThresholdV2();
