use std::convert::TryInto;
use std::marker::PhantomData;

use crate::{Hasher, utils};
pub use crate::error::Error;
pub use crate::error::ErrorKind;

pub struct MerkleProof<T: Hasher> {
    proof_hashes: Vec<T::Hash>,
    _hasher: PhantomData<T>,
}

impl<T: Hasher> MerkleProof<T> {
    /// MerkleProof requires specifying hashing algorithm and hash size in order to work.
    /// It uses Hasher trait from the crate to do that. An sha256 implementation of Hasher
    /// could look like this:
    /// ```
    /// use rs_merkle::Hasher;
    /// use sha2::{Sha256, Digest, digest::FixedOutput};
    ///
    /// #[derive(Clone)]
    /// pub struct Sha256Hasher {}
    ///
    /// impl Hasher for Sha256Hasher {
    ///     // The size of sha256 is 32 bytes
    ///     type Hash = [u8; 32];
    ///
    ///     fn hash(data: &Vec<u8>) -> [u8; 32] {
    ///         let mut hasher = Sha256::new();
    ///
    ///         hasher.update(data);
    ///         <[u8; 32]>::from(hasher.finalize_fixed())
    ///     }
    /// }
    /// ```
    pub fn new(proof_hashes: Vec<T::Hash>) -> Self {
        MerkleProof {
            proof_hashes,
            _hasher: PhantomData
        }
    }

    /// Parses proof serialized as bytes
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

    pub fn proof_hashes(&self) -> &Vec<T::Hash> {
        &self.proof_hashes
    }

    pub fn hex_proof_hashes(&self) -> Vec<String> {
        self.proof_hashes
            .iter()
            .map(utils::collections::to_hex_string)
            .collect()
    }

    /// Calculates merkle root bases on provided leaves and proof hashes
    pub fn root(&self, leaf_indices: &Vec<usize>, leaf_hashes: &Vec<T::Hash>, total_leaves_count: usize) -> T::Hash {
        // Zipping indices and hashes into a vector of (original_index_in_tree, leaf_hash)
        let mut leaf_tuples: Vec<(usize, T::Hash)> = leaf_indices.iter().cloned().zip(leaf_hashes.iter().cloned()).collect();
        // Sorting leaves by indexes in case they weren't sorted already
        leaf_tuples.sort_by(|(a, _), (b, _)| a.cmp(b));
        // Getting back _sorted_ indices
        let proof_indices = utils::indices::proof_indices(leaf_indices, total_leaves_count);

        let mut proof_layers: Vec<Vec<(usize, T::Hash)>> = Vec::new();

        let mut next_slice_start = 0;
        for indices in proof_indices {
            let slice_start = next_slice_start;
            next_slice_start += indices.len();

            let hashes = self.proof_hashes.get(slice_start..next_slice_start).unwrap();
            proof_layers.push(indices.iter().cloned().zip(hashes.iter().cloned()).collect());
        }

        let mut partial_tree = vec![leaf_tuples];

        for layer_index in 0..proof_layers.len() {
            let mut current_layer = partial_tree.get(layer_index).unwrap().clone();
            let mut current_proofs = proof_layers.get(layer_index).unwrap().clone();

            current_layer.append(&mut current_proofs);
            current_layer.sort_by(|(a, _), (b, _)| a.cmp(b));

            let (indices, hashes): (Vec<usize>, Vec<T::Hash>) = current_layer.drain(..).unzip();
            let parent_layer_indices = utils::indices::parent_indices(&indices);

            let parent_layer = parent_layer_indices
                .iter()
                .cloned()
                .enumerate()
                .map(|(i, parent_node_index)| (
                    parent_node_index,
                    T::concat_and_hash(
                        hashes.get(i * 2),
                        hashes.get(i * 2 + 1)
                    ))
                )
                .collect();

            partial_tree.push(parent_layer);
        }

        return partial_tree.last().unwrap().first().unwrap().1.clone();
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