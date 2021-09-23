use crate::{Hasher, utils};

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

    pub fn proof_hashes(&self) -> &Vec<Vec<u8>> {
        &self.proof_hashes
    }

    pub fn hex_proof_hashes(&self) -> Vec<String> {
        self.proof_hashes
            .iter()
            .map(utils::collections::to_hex_string)
            .collect()
    }
}