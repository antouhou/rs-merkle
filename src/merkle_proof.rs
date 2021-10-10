use std::convert::TryFrom;

use crate::error::Error;
use crate::partial_tree::PartialTree;
use crate::{utils, Hasher};

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
        MerkleProof { proof_hashes }
    }

    /// Parses proof serialized as bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        let hash_size = T::hash_size();

        if bytes.len() % hash_size != 0 {
            return Err(Error::wrong_proof_size(bytes.len(), hash_size));
        }

        let hashes_count = bytes.len() / hash_size;
        let mut proof_hashes_slices = Vec::<T::Hash>::with_capacity(hashes_count);

        for i in 0..hashes_count {
            let slice_start = i * hash_size;
            let slice_end = (i + 1) * hash_size;
            let slice = bytes.get(slice_start..slice_end).unwrap();
            let vec = Vec::<u8>::try_from(slice).unwrap();
            match T::Hash::try_from(vec) {
                Ok(val) => proof_hashes_slices.push(val),
                Err(_) => return Err(Error::vec_to_hash_conversion_error()),
            }
        }

        Ok(Self::new(proof_hashes_slices))
    }

    /// Returns
    pub fn proof_hashes(&self) -> &[T::Hash] {
        &self.proof_hashes
    }

    pub fn hex_proof_hashes(&self) -> Vec<String> {
        self.proof_hashes
            .iter()
            .map(utils::collections::to_hex_string)
            .collect()
    }

    /// Calculates merkle root based on provided leaves and proof hashes
    pub fn root(
        &self,
        leaf_indices: &[usize],
        leaf_hashes: &[T::Hash],
        total_leaves_count: usize,
    ) -> T::Hash {
        let tree_depth = utils::indices::tree_depth(total_leaves_count);

        // Zipping indices and hashes into a vector of (original_index_in_tree, leaf_hash)
        let mut leaf_tuples: Vec<(usize, T::Hash)> = leaf_indices
            .iter()
            .cloned()
            .zip(leaf_hashes.iter().cloned())
            .collect();
        // Sorting leaves by indexes in case they weren't sorted already
        leaf_tuples.sort_by(|(a, _), (b, _)| a.cmp(b));
        // Getting back _sorted_ indices
        let proof_indices_by_layers =
            utils::indices::proof_indices_by_layers(leaf_indices, total_leaves_count);

        // The next lines copy hashes from proof hashes and group them by layer index
        let mut proof_layers: Vec<Vec<(usize, T::Hash)>> = Vec::with_capacity(tree_depth + 1);
        let mut proof_copy = self.proof_hashes.clone();
        for proof_indices in proof_indices_by_layers {
            let proof_hashes = proof_copy.splice(0..proof_indices.len(), []);
            proof_layers.push(proof_indices.iter().cloned().zip(proof_hashes).collect());
        }

        match proof_layers.first_mut() {
            Some(first_layer) => {
                first_layer.append(&mut leaf_tuples);
                first_layer.sort_by(|(a, _), (b, _)| a.cmp(b));
            }
            None => proof_layers.push(leaf_tuples),
        }

        // TODO: remove the unwrap!
        let partial_tree = PartialTree::<T>::build(proof_layers, tree_depth).unwrap();

        *partial_tree.root().unwrap()
    }

    /// Calculates the root and serializes it into a hex string
    pub fn hex_root(
        &self,
        leaf_indices: &[usize],
        leaf_hashes: &[T::Hash],
        total_leaves_count: usize,
    ) -> String {
        let root = self.root(leaf_indices, leaf_hashes, total_leaves_count);
        utils::collections::to_hex_string(&root)
    }

    /// Verifies
    pub fn verify(
        &self,
        root: T::Hash,
        leaf_indices: &[usize],
        leaf_hashes: &[T::Hash],
        total_leaves_count: usize,
    ) -> bool {
        let extracted_root = self.root(leaf_indices, leaf_hashes, total_leaves_count);
        root == extracted_root
    }

    /// Serializes proof hashes to a flat vector of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let vectors: Vec<Vec<u8>> = self
            .proof_hashes()
            .iter()
            .cloned()
            .map(|hash| hash.into())
            .collect();
        vectors.iter().cloned().flatten().collect()
    }
}
