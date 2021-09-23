use rs_merkle::Hasher;
use sha2::{Sha256, Digest};

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

pub struct TestData {
    pub test_hasher: TestHasher,
    pub leaf_values: Vec<String>,
    pub expected_root_hex: String,
    pub leaf_hashes: Vec<Vec<u8>>,
}

pub fn setup() -> TestData {
    let test_hasher = TestHasher::new();
    let leaf_values = ["a", "b", "c", "d", "e", "f"];
    let expected_root_hex = "1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2";
    let leaf_hashes = leaf_values
        .iter()
        .map(|x| TestHasher::hash(x.as_bytes().to_vec().as_ref()))
        .collect();

    TestData {
        test_hasher,
        leaf_values: leaf_values.iter().cloned().map(String::from).collect(),
        leaf_hashes,
        expected_root_hex: String::from(expected_root_hex)
    }
}
