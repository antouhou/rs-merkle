use sha2::{Sha256, Digest};
use crate::{Hasher, utils};

#[derive(Clone)]
pub struct TestHasher {}

impl TestHasher {
    pub fn new() -> Self { TestHasher {} }
}

impl Hasher for TestHasher {
    fn hash(data: &Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();

        hasher.update(data);
        hasher.finalize().to_owned().to_vec()
    }
}

pub mod get_root {
    use crate::{MerkleTree, utils, Hasher};
    use sha2::Sha256;
    use crate::tests::TestHasher;

    #[test]
    pub fn should_get_a_correct_root() {
        let test_hasher = TestHasher::new();
        let leaf_values = ["a", "b", "c", "d", "e", "f"];
        let expected_root_hex = "1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2";

        let leaf_hashes = leaf_values
            .iter()
            .map(|x| TestHasher::hash(x.as_bytes().to_vec().as_ref()))
            .collect();

        let merkle_tree = MerkleTree::new(leaf_hashes, test_hasher);
        let root = merkle_tree.get_root();
        let hex_root = utils::collections::to_hex_string(&root.unwrap());

        assert_eq!(hex_root, expected_root_hex);
    }
}