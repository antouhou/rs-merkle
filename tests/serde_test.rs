use rs_merkle::{
    algorithms::{Sha256, Sha384},
    MerkleProof, MerkleTree,
};

// Asserts that a value implements the Serialize and Deserialize traits
fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}

#[test]
fn test_serde() {
    assert_serde::<MerkleTree<Sha256>>();
    assert_serde::<MerkleTree<Sha384>>();
    assert_serde::<MerkleProof<Sha256>>();
    assert_serde::<MerkleProof<Sha384>>();
}
