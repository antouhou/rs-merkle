use std::convert::TryInto;

use crate::{Hasher, utils};
use crate::error::Error;
use crate::error::ErrorKind;
use crate::partial_tree::PartialTree;

/// `MerkleProof` is used to parse, verify, calculate a root for merkle proofs.
///
/// # Usage
///
/// MerkleProof requires specifying hashing algorithm and hash size in order to work.
/// Check out the `Hasher` trait for examples. rs_merkle provides some built in `Hasher`
/// implementations, for example `rs_merkle::algorithms::Sha256`
///
/// # Example
///
/// ```
/// use rs_merkle::{MerkleProof, algorithms::Sha256};
/// let proof_hashes: Vec<[u8; 32]> = vec![
///
/// ];
///
/// let proof = MerkleProof::<Sha256>::new(proof_hashes);
///```
pub struct MerkleProof<T: Hasher> {
    proof_hashes: Vec<T::Hash>,
}

impl<T: Hasher> MerkleProof<T> {
    pub fn new(proof_hashes: Vec<T::Hash>) -> Self {
        MerkleProof {
            proof_hashes,
        }
    }

    /// Parses proof serialized as bytes
    ///
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        let hash_size = T::hash_size();

        if bytes.len() % hash_size != 0 {
            return Err(Error::new(
                ErrorKind::SerializedProofSizeIsIncorrect,
                format!("Proof of size {} bytes can not be divided into chunks of {} bytes", bytes.len(), hash_size)));
        }

        let hashes_count = bytes.len() / hash_size;
        let proof_hashes_slices: Vec<T::Hash> = (0..hashes_count)
            .map(|i| {
                let x: Vec<u8> = bytes.get(i * hash_size..(i + 1) * hash_size).unwrap().try_into().unwrap();
                match x.try_into() {
                    Ok(val) => val,
                    // Because of the check above the initial bytes are always slices perfectly
                    // into appropriately sized hashes.
                    // Unwrap is not used here due to more complex trait bounds on T::Hash
                    // that would be require to satisfy .unwrap usage
                    Err(_) => panic!("Unexpected error during proof parsing")
                }
            })
            .collect();

        Ok(Self::new(proof_hashes_slices))
    }

    /// Returns
    pub fn proof_hashes(&self) -> &Vec<T::Hash> {
        &self.proof_hashes
    }

    pub fn hex_proof_hashes(&self) -> Vec<String> {
        self.proof_hashes
            .iter()
            .map(utils::collections::to_hex_string)
            .collect()
    }

    /// Calculates merkle root based on provided leaves and proof hashes
    pub fn root(&self, leaf_indices: &Vec<usize>, leaf_hashes: &Vec<T::Hash>, total_leaves_count: usize) -> T::Hash {
        // Zipping indices and hashes into a vector of (original_index_in_tree, leaf_hash)
        let mut leaf_tuples: Vec<(usize, T::Hash)> = leaf_indices.iter().cloned().zip(leaf_hashes.iter().cloned()).collect();
        // Sorting leaves by indexes in case they weren't sorted already
        leaf_tuples.sort_by(|(a, _), (b, _)| a.cmp(b));
        // Getting back _sorted_ indices
        let proof_indices_by_layers = utils::indices::proof_indices(leaf_indices, total_leaves_count);

        let mut proof_layers: Vec<Vec<(usize, T::Hash)>> = Vec::new();

        let mut next_slice_start = 0;
        for proof_indices in proof_indices_by_layers {
            let slice_start = next_slice_start;
            next_slice_start += proof_indices.len();

            let proof_hashes = self.proof_hashes.get(slice_start..next_slice_start).unwrap();
            proof_layers.push(proof_indices.iter().cloned().zip(proof_hashes.iter().cloned()).collect());
        }

        // TODO: remove the unwrap!
        let partial_tree = PartialTree::<T>::build(&leaf_tuples, &proof_layers, proof_layers.len()).unwrap();

        return partial_tree.root().unwrap().clone();
    }

    /// Calculates the root and serializes it into a hex string
    pub fn hex_root(&self, leaf_indices: &Vec<usize>, leaf_hashes: &Vec<T::Hash>, total_leaves_count: usize) -> String {
        let root = self.root(leaf_indices, leaf_hashes, total_leaves_count);
        utils::collections::to_hex_string(&root)
    }

    /// Verifies
    pub fn verify(&self, root: T::Hash, leaf_indices: &Vec<usize>, leaf_hashes: &Vec<T::Hash>, total_leaves_count: usize) -> bool {
        let extracted_root = self.root(leaf_indices, leaf_hashes, total_leaves_count);
        root == extracted_root
    }

    /// Serializes proof hashes to a flat vector of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let vectors: Vec<Vec<u8>> = self.proof_hashes().iter().cloned().map(|hash| hash.into()).collect();
        vectors.iter().cloned().flatten().collect()
    }
}