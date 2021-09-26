mod common;

pub mod root {
    use crate::common;
    use rs_merkle::{MerkleTree, algorithms::Sha256};

    #[test]
    pub fn should_return_a_correct_root() {
        let test_data = common::setup();

        let merkle_tree = MerkleTree::<Sha256>::new(&test_data.leaf_hashes);
        let hex_root = merkle_tree.root_hex().unwrap();

        assert_eq!(hex_root, test_data.expected_root_hex);
    }
}

pub mod tree_depth {
    use crate::common;
    use rs_merkle::{MerkleTree, algorithms::Sha256};

    #[test]
    pub fn should_return_a_correct_tree_depth() {
        let test_data = common::setup();

        let merkle_tree = MerkleTree::<Sha256>::new(&test_data.leaf_hashes);

        let depth = merkle_tree.depth();
        assert_eq!(depth, 3)
    }
}

pub mod proof {
    use crate::common;
    use rs_merkle::{MerkleTree, algorithms::Sha256};

    #[test]
    pub fn should_return_a_correct_proof() {
        let test_data = common::setup();
        let indices_to_prove = vec![3, 4];
        let expected_proof_hashes = [
            "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6",
            "252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111",
            "e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a",
        ];

        let merkle_tree = MerkleTree::<Sha256>::new(&test_data.leaf_hashes);
        let proof = merkle_tree.proof(&indices_to_prove);
        let proof_hashes = proof.hex_proof_hashes();

        assert_eq!(proof_hashes, expected_proof_hashes)
    }
}