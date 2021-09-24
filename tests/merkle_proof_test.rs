mod common;

pub mod root {
    use crate::common;
    use rs_merkle::{MerkleTree, utils};

    #[test]
    pub fn should_return_a_correct_root() {
        let test_data = common::setup();
        let expected_root = &test_data.expected_root_hex;
        let leaf_hashes = &test_data.leaf_hashes;
        let indices_to_prove = vec![3, 4];
        let leaves_to_prove = indices_to_prove.iter().cloned().map(|i| leaf_hashes.get(i).unwrap().clone()).collect();

        let merkle_tree = MerkleTree::new(test_data.leaf_hashes.to_vec(), test_data.test_hasher.clone());
        let proof = merkle_tree.proof(&indices_to_prove);
        let extracted_root = proof.hex_root(&indices_to_prove, &leaves_to_prove, test_data.leaf_values.len());

        assert_eq!(extracted_root, *expected_root)
    }
}