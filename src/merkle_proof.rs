use crate::Hasher;

pub struct MerkleProof<T> {
    proof_hashes: Vec<Vec<u8>>,
    hasher: T
}

impl<T: Hasher> MerkleProof<T> {
    pub fn new(proof_hashes: Vec<Vec<u8>>, hasher: &T) -> Self {
        MerkleProof {
            proof_hashes, hasher: hasher.clone()
        }
    }
}