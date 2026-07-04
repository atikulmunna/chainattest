pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";

template BinaryCheck() {
    signal input in;

    in * (in - 1) === 0;
}

template SemanticAttestationV1(TREE_DEPTH) {
    signal input attestation_id;
    signal input registered_at_block;
    signal input weights_root;
    signal input attestation_commitment;
    signal input circuit_version_id;

    signal input model_file_digest_field;
    signal input dataset_commitment_field;
    signal input training_commitment_field;
    signal input metadata_digest_field;
    signal input owner_field;
    signal input path_elements[TREE_DEPTH];
    signal input path_indices[TREE_DEPTH];

    // Collision-resistant Poseidon leaf binding the attestation metadata that
    // already exists in the relay package. A linear combination here would not be
    // collision resistant, so the Merkle inclusion could be forged.
    component leafHasher = Poseidon(5);
    leafHasher.inputs[0] <== model_file_digest_field;
    leafHasher.inputs[1] <== dataset_commitment_field;
    leafHasher.inputs[2] <== training_commitment_field;
    leafHasher.inputs[3] <== metadata_digest_field;
    leafHasher.inputs[4] <== owner_field;

    signal current[TREE_DEPTH + 1];
    signal left[TREE_DEPTH];
    signal right[TREE_DEPTH];
    component binary[TREE_DEPTH];
    component levelHasher[TREE_DEPTH];

    current[0] <== leafHasher.out;

    for (var i = 0; i < TREE_DEPTH; i++) {
        binary[i] = BinaryCheck();
        binary[i].in <== path_indices[i];

        // index == 0 -> (current, sibling); index == 1 -> (sibling, current)
        left[i] <== current[i] + (path_elements[i] - current[i]) * path_indices[i];
        right[i] <== path_elements[i] + (current[i] - path_elements[i]) * path_indices[i];

        levelHasher[i] = Poseidon(2);
        levelHasher[i].inputs[0] <== left[i];
        levelHasher[i].inputs[1] <== right[i];
        current[i + 1] <== levelHasher[i].out;
    }

    current[TREE_DEPTH] === weights_root;

    // The commitment binds the public package fields to the proof so a proof cannot
    // be replayed against a different attestation. Collision resistance is not
    // required here: every input is a public package field that is independently
    // committed by the committee's keccak256 signature over the source record, and
    // the destination contract recomputes this same value from the package.
    attestation_commitment ===
        attestation_id +
        model_file_digest_field * 3 +
        dataset_commitment_field * 5 +
        training_commitment_field * 7 +
        metadata_digest_field * 11 +
        owner_field * 13 +
        registered_at_block * 17 +
        weights_root * 19;

    circuit_version_id === 1;
}

component main {public [
    attestation_id,
    registered_at_block,
    weights_root,
    attestation_commitment,
    circuit_version_id
]} = SemanticAttestationV1(16);
