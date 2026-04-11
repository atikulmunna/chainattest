pragma circom 2.1.9;

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

    signal current[TREE_DEPTH + 1];
    signal left[TREE_DEPTH];
    signal right[TREE_DEPTH];
    component binary[TREE_DEPTH];

    // Bind the Merkle leaf to the attestation metadata that already exists in the relay package.
    current[0] <==
        model_file_digest_field +
        dataset_commitment_field * 2 +
        training_commitment_field * 3 +
        metadata_digest_field * 5 +
        owner_field * 7;

    for (var i = 0; i < TREE_DEPTH; i++) {
        binary[i] = BinaryCheck();
        binary[i].in <== path_indices[i];

        left[i] <== current[i] + (path_elements[i] - current[i]) * path_indices[i];
        right[i] <== path_elements[i] + (current[i] - path_elements[i]) * path_indices[i];
        current[i + 1] <== left[i] * 17 + right[i] * 31 + (i + 1);
    }

    current[TREE_DEPTH] === weights_root;

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
]} = SemanticAttestationV1(2);
