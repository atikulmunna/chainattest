pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

// Blinded evaluation-threshold statement (eval circuit version 4).
//
// The destination chain never sees a count. Public inputs are the claim context
// (attestation id, benchmark digest), two hiding Poseidon commitments, the
// threshold, a minimum sample size, and the verdict bit. The per-batch transcript
// summary, its evaluation-configuration digests, and both blinding randomizers
// stay in the private witness.
//
//   K = sum_i correct_i                     (correct predictions)
//   N = sum_i (correct_i + incorrect_i + abstain_i)   (evaluated samples)
//   transcript_commitment = Poseidon(context, config, Poseidon(batch summary), r_T)
//   score_commitment      = Poseidon(K, N, r_S)
//   verdict               = [K * 10000 >= threshold_bps * N]
//
// Every count is range-checked to COUNT_BITS bits and every comparison operand is
// bounded well below the comparator width, so no product or sum can wrap modulo
// the BN254 scalar field.
template BlindedEvalThreshold(MAX_BATCHES, COUNT_BITS) {
    // Public inputs, declared in public-signal order.
    signal input attestation_id;
    signal input benchmark_digest_field;
    signal input transcript_commitment;
    signal input score_commitment;
    signal input threshold_bps;
    signal input min_sample_count;
    signal input verdict;
    signal input circuit_version_id;

    // Private witness.
    signal input dataset_split_digest_field;
    signal input inference_config_digest_field;
    signal input randomness_seed_digest_field;
    signal input transcript_version;
    signal input batch_count;
    signal input batch_correct_counts[MAX_BATCHES];
    signal input batch_incorrect_counts[MAX_BATCHES];
    signal input batch_abstain_counts[MAX_BATCHES];
    signal input transcript_blinding;
    signal input score_blinding;

    var BATCH_BITS = 3;
    var CMP_BITS = 64;

    // Batch structure: 1 <= batch_count <= MAX_BATCHES.
    component batchCountBits = Num2Bits(BATCH_BITS);
    batchCountBits.in <== batch_count;
    component batchCountMin = GreaterEqThan(BATCH_BITS);
    batchCountMin.in[0] <== batch_count;
    batchCountMin.in[1] <== 1;
    batchCountMin.out === 1;
    component batchCountMax = LessEqThan(BATCH_BITS);
    batchCountMax.in[0] <== batch_count;
    batchCountMax.in[1] <== MAX_BATCHES;
    batchCountMax.out === 1;

    // Condition 1, count validity: every per-batch count is a COUNT_BITS-bit
    // integer, so N_i = K_i + I_i + A_i satisfies 0 <= K_i <= N_i over the
    // integers. Batches at index >= batch_count must be empty and batches below it
    // must be non-empty, which keeps the committed summary canonical.
    component correctBits[MAX_BATCHES];
    component incorrectBits[MAX_BATCHES];
    component abstainBits[MAX_BATCHES];
    component batchActive[MAX_BATCHES];
    component batchEmpty[MAX_BATCHES];
    signal batch_total[MAX_BATCHES];
    signal correct_acc[MAX_BATCHES + 1];
    signal sample_acc[MAX_BATCHES + 1];
    correct_acc[0] <== 0;
    sample_acc[0] <== 0;

    for (var i = 0; i < MAX_BATCHES; i++) {
        correctBits[i] = Num2Bits(COUNT_BITS);
        correctBits[i].in <== batch_correct_counts[i];
        incorrectBits[i] = Num2Bits(COUNT_BITS);
        incorrectBits[i].in <== batch_incorrect_counts[i];
        abstainBits[i] = Num2Bits(COUNT_BITS);
        abstainBits[i].in <== batch_abstain_counts[i];

        batch_total[i] <== batch_correct_counts[i] + batch_incorrect_counts[i] + batch_abstain_counts[i];

        batchActive[i] = LessThan(BATCH_BITS);
        batchActive[i].in[0] <== i;
        batchActive[i].in[1] <== batch_count;
        (1 - batchActive[i].out) * batch_total[i] === 0;

        batchEmpty[i] = IsZero();
        batchEmpty[i].in <== batch_total[i];
        batchActive[i].out * batchEmpty[i].out === 0;

        // Condition 2, total consistency: K = sum K_i and N = sum N_i.
        correct_acc[i + 1] <== correct_acc[i] + batch_correct_counts[i];
        sample_acc[i + 1] <== sample_acc[i] + batch_total[i];
    }

    signal correct_total;
    signal sample_total;
    correct_total <== correct_acc[MAX_BATCHES];
    sample_total <== sample_acc[MAX_BATCHES];

    // Public parameters: 0 <= threshold_bps <= 10000 and
    // 1 <= min_sample_count < 2^COUNT_BITS, with N >= min_sample_count so a hidden
    // N cannot rest the verdict on a trivially small (or empty) sample.
    component thresholdBits = Num2Bits(14);
    thresholdBits.in <== threshold_bps;
    component thresholdMax = LessEqThan(14);
    thresholdMax.in[0] <== threshold_bps;
    thresholdMax.in[1] <== 10000;
    thresholdMax.out === 1;

    component minSampleBits = Num2Bits(COUNT_BITS);
    minSampleBits.in <== min_sample_count;
    component minSampleNonZero = IsZero();
    minSampleNonZero.in <== min_sample_count;
    minSampleNonZero.out === 0;
    component enoughSamples = GreaterEqThan(CMP_BITS);
    enoughSamples.in[0] <== sample_total;
    enoughSamples.in[1] <== min_sample_count;
    enoughSamples.out === 1;

    // Condition 3, threshold: K / N >= threshold_bps / 10000, evaluated without
    // division as K * 10000 >= threshold_bps * N. The verdict is an output of the
    // comparison, not an assertion, so the same circuit proves PASS and FAIL.
    signal scaled_threshold;
    scaled_threshold <== threshold_bps * sample_total;
    component meetsThreshold = GreaterEqThan(CMP_BITS);
    meetsThreshold.in[0] <== correct_total * 10000;
    meetsThreshold.in[1] <== scaled_threshold;
    verdict === meetsThreshold.out;

    // Condition 4, transcript commitment: the full per-batch summary and its
    // evaluation configuration, bound to the claim context and blinded by r_T.
    component batchSummary = Poseidon(1 + 3 * MAX_BATCHES);
    batchSummary.inputs[0] <== batch_count;
    for (var i = 0; i < MAX_BATCHES; i++) {
        batchSummary.inputs[1 + 3 * i] <== batch_correct_counts[i];
        batchSummary.inputs[2 + 3 * i] <== batch_incorrect_counts[i];
        batchSummary.inputs[3 + 3 * i] <== batch_abstain_counts[i];
    }

    component transcriptHasher = Poseidon(8);
    transcriptHasher.inputs[0] <== attestation_id;
    transcriptHasher.inputs[1] <== benchmark_digest_field;
    transcriptHasher.inputs[2] <== dataset_split_digest_field;
    transcriptHasher.inputs[3] <== inference_config_digest_field;
    transcriptHasher.inputs[4] <== randomness_seed_digest_field;
    transcriptHasher.inputs[5] <== transcript_version;
    transcriptHasher.inputs[6] <== batchSummary.out;
    transcriptHasher.inputs[7] <== transcript_blinding;
    transcriptHasher.out === transcript_commitment;

    // Condition 5, score commitment: the aggregate (K, N) blinded by r_S, so the
    // exact score can later be opened without revealing the per-batch transcript.
    component scoreHasher = Poseidon(3);
    scoreHasher.inputs[0] <== correct_total;
    scoreHasher.inputs[1] <== sample_total;
    scoreHasher.inputs[2] <== score_blinding;
    scoreHasher.out === score_commitment;

    circuit_version_id === 4;
}

component main {public [
    attestation_id,
    benchmark_digest_field,
    transcript_commitment,
    score_commitment,
    threshold_bps,
    min_sample_count,
    verdict,
    circuit_version_id
]} = BlindedEvalThreshold(4, 32);
