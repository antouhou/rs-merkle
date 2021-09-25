mod common;

pub mod root {
    use crate::{common, common::Sha256Hasher};
    use rs_merkle::{MerkleTree};
    use std::time::Instant;
    use rayon::prelude::*;

    #[test]
    pub fn should_return_a_correct_root() {
        let test_data = common::setup();
        let expected_root = &test_data.expected_root_hex;
        let leaf_hashes = &test_data.leaf_hashes;
        let indices_to_prove = vec![3, 4];
        let leaves_to_prove = indices_to_prove.iter().cloned().map(|i| leaf_hashes.get(i).unwrap().clone()).collect();

        let merkle_tree = MerkleTree::<Sha256Hasher>::new(&test_data.leaf_hashes);
        let proof = merkle_tree.proof(&indices_to_prove);
        let extracted_root = proof.hex_root(&indices_to_prove, &leaves_to_prove, test_data.leaf_values.len());

        assert_eq!(extracted_root, *expected_root);

        let test_preparation_started = Instant::now();
        let test_cases = common::setup_proof_test_cases();
        println!("Preparing test cases took {:.2}s", test_preparation_started.elapsed().as_secs_f32());
        let test_cases_count = test_cases.iter().fold(0, |acc, case| acc + case.cases.len());

        let test_run_started = Instant::now();
        test_cases.par_iter().for_each(|test_case| {
           let merkle_tree = &test_case.merkle_tree;

            test_case.cases.par_iter().for_each(|case| {
                let proof = merkle_tree.proof(&case.leaf_indices_to_prove);
                let root = merkle_tree.hex_root().unwrap();
                let extracted_root = proof.hex_root(&case.leaf_indices_to_prove, &case.leaf_hashes_to_prove, merkle_tree.leaves().unwrap().len());

                assert_eq!(extracted_root, root)
            });
        });
        println!("{} test cases executed in {:.2}s", test_cases_count, test_run_started.elapsed().as_secs_f32());
    }
}

pub mod to_bytes {
    use crate::{common, common::Sha256Hasher};
    use rs_merkle::MerkleTree;

    #[test]
    pub fn should_correctly_serialize_to_bytes() {
        let expected_bytes: Vec<u8> = vec![
            46, 125,  44,   3, 169,  80, 122, 226, 101, 236, 245, 181,
            53, 104, 133, 165,  51, 147, 162,   2, 157,  36,  19, 148,
            153, 114, 101, 161, 162,  90, 239, 198,  37,  47,  16, 200,
            54,  16, 235, 202,  26,   5, 156,  11, 174, 130,  85, 235,
            162, 249,  91, 228, 209, 215, 188, 250, 137, 215,  36, 138,
            130, 217, 241,  17, 229, 160,  31, 238,  20, 224, 237,  92,
            72, 113,  79,  34,  24,  15,  37, 173, 131, 101, 181,  63,
            151, 121, 247, 157, 196, 163, 215, 233,  57,  99, 249,  74
        ];

        let test_data = common::setup();
        let indices_to_prove = vec![3, 4];
        let merkle_tree = MerkleTree::<Sha256Hasher>::new(&test_data.leaf_hashes);
        let proof = merkle_tree.proof(&indices_to_prove);

        let bytes = proof.to_bytes();

        assert_eq!(bytes, expected_bytes);
    }
}

pub mod from_bytes {
    use rs_merkle::MerkleProof;
    use crate::common::Sha256Hasher;

    #[test]
    pub fn should_return_result_with_proof() {
        let expected_proof_hashes = [
            "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6",
            "252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111",
            "e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a",
        ];

        let bytes: Vec<u8> = vec![
            46, 125,  44,   3, 169,  80, 122, 226, 101, 236, 245, 181,
            53, 104, 133, 165,  51, 147, 162,   2, 157,  36,  19, 148,
            153, 114, 101, 161, 162,  90, 239, 198,  37,  47,  16, 200,
            54,  16, 235, 202,  26,   5, 156,  11, 174, 130,  85, 235,
            162, 249,  91, 228, 209, 215, 188, 250, 137, 215,  36, 138,
            130, 217, 241,  17, 229, 160,  31, 238,  20, 224, 237,  92,
            72, 113,  79,  34,  24,  15,  37, 173, 131, 101, 181,  63,
            151, 121, 247, 157, 196, 163, 215, 233,  57,  99, 249,  74
        ];

        let proof = MerkleProof::<Sha256Hasher>::from_bytes(bytes).unwrap();
        let hex_hashes = proof.hex_proof_hashes();

        assert_eq!(hex_hashes, expected_proof_hashes);
    }

    #[test]
    pub fn should_return_error_when_proof_can_not_be_parsed() {
        let bytes: Vec<u8> = vec![
            46, 125,  44,   3, 169,  80, 122, 226, 101, 236, 245, 181,
            53, 104, 133, 165,  51, 147, 162,   2, 157,  36,  19, 148,
            153, 114, 101, 161, 162,  90, 239, 198,  37,  47,  16, 200,
            54,  16, 235, 202,  26,   5, 156,  11, 174, 130,  85, 235,
            162, 249,  91, 228, 209, 215, 188, 250, 137, 215,  36, 138,
            130, 217, 241,  17, 229, 160,  31, 238,  20, 224, 237,  92,
            72, 113,  79,  34,  24,  15,  37, 173, 131, 101, 181,  63,
        ];

        let err = MerkleProof::<Sha256Hasher>::from_bytes(bytes).err().unwrap();

        assert_eq!(err.message(), "Proof of size 84 bytes can not be divided into chunks of 32 bytes");
    }
}