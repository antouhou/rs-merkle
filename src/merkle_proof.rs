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

    /// Creates a proof from a slice of bytes. For more details and examples, please see
    /// [`try_from`](MerkleProof::try_from)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::try_from(bytes)
    }

    /// Returns all hashes from the proof, sorted from the left to right,
    /// bottom to top.
    pub fn proof_hashes(&self) -> &[T::Hash] {
        &self.proof_hashes
    }

    /// Returns all hashes from the proof, sorted from the left to right,
    /// bottom to top, as a vector of lower hex strings.
    /// For a slice of `&[Hasher::Hash]`, see [`proof_hashes`](MerkleProof::proof_hashes)
    pub fn proof_hashes_hex(&self) -> Vec<String> {
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
    ) -> Result<T::Hash, Error> {
        if leaf_indices.len() != leaf_hashes.len() {
            return Err(Error::leaves_indices_count_mismatch(
                leaf_indices.len(),
                leaf_hashes.len(),
            ));
        }
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

        let partial_tree = PartialTree::<T>::build(proof_layers, tree_depth)?;

        match partial_tree.root() {
            Some(root) => Ok(*root),
            None => Err(Error::not_enough_hashes_to_calculate_root()),
        }
    }

    /// Calculates the root and serializes it into a hex string
    pub fn root_hex(
        &self,
        leaf_indices: &[usize],
        leaf_hashes: &[T::Hash],
        total_leaves_count: usize,
    ) -> Result<String, Error> {
        let root = self.root(leaf_indices, leaf_hashes, total_leaves_count)?;
        Ok(utils::collections::to_hex_string(&root))
    }

    /// Verifies the proof for a given set of leaves
    pub fn verify(
        &self,
        root: T::Hash,
        leaf_indices: &[usize],
        leaf_hashes: &[T::Hash],
        total_leaves_count: usize,
    ) -> bool {
        match self.root(leaf_indices, leaf_hashes, total_leaves_count) {
            Ok(extracted_root) => extracted_root == root,
            Err(_) => false,
        }
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

impl<T: Hasher> TryFrom<Vec<u8>> for MerkleProof<T> {
    type Error = Error;

    /// Parses proof serialized to a collection of bytes. Consumes passed vector.
    ///
    /// # Example
    /// ```
    /// use std::convert::TryFrom;
    /// use rs_merkle::{MerkleProof, algorithms::Sha256};
    ///
    /// let proof_bytes: Vec<u8> = vec![
    ///     46, 125, 44, 3, 169, 80, 122, 226, 101, 236, 245, 181, 53, 104, 133, 165, 51, 147, 162,
    ///     2, 157, 36, 19, 148, 153, 114, 101, 161, 162, 90, 239, 198, 37, 47, 16, 200, 54, 16,
    ///     235, 202, 26, 5, 156, 11, 174, 130, 85, 235, 162, 249, 91, 228, 209, 215, 188, 250,
    ///     137, 215, 36, 138, 130, 217, 241, 17, 229, 160, 31, 238, 20, 224, 237, 92, 72, 113, 79,
    ///     34, 24, 15, 37, 173, 131, 101, 181, 63, 151, 121, 247, 157, 196, 163, 215, 233, 57, 99,
    ///     249, 74,
    /// ];
    ///
    /// let proof_result = MerkleProof::<Sha256>::try_from(proof_bytes);
    /// ```
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        MerkleProof::from_bytes(&bytes)
    }
}

impl<T: Hasher> TryFrom<&[u8]> for MerkleProof<T> {
    type Error = Error;

    /// Parses proof serialized to a collection of bytes
    ///
    /// # Example
    /// ```
    /// use std::convert::TryFrom;
    /// use rs_merkle::{MerkleProof, algorithms::Sha256};
    ///
    /// let proof_bytes: Vec<u8> = vec![
    ///     46, 125, 44, 3, 169, 80, 122, 226, 101, 236, 245, 181, 53, 104, 133, 165, 51, 147, 162,
    ///     2, 157, 36, 19, 148, 153, 114, 101, 161, 162, 90, 239, 198, 37, 47, 16, 200, 54, 16,
    ///     235, 202, 26, 5, 156, 11, 174, 130, 85, 235, 162, 249, 91, 228, 209, 215, 188, 250,
    ///     137, 215, 36, 138, 130, 217, 241, 17, 229, 160, 31, 238, 20, 224, 237, 92, 72, 113, 79,
    ///     34, 24, 15, 37, 173, 131, 101, 181, 63, 151, 121, 247, 157, 196, 163, 215, 233, 57, 99,
    ///     249, 74,
    /// ];
    ///
    /// let proof_result = MerkleProof::<Sha256>::try_from(proof_bytes.as_slice());
    /// ```
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let hash_size = T::hash_size();

        if bytes.len() % hash_size != 0 {
            return Err(Error::wrong_proof_size(bytes.len(), hash_size));
        }

        let hashes_count = bytes.len() / hash_size;
        let mut proof_hashes_slices = Vec::<T::Hash>::with_capacity(hashes_count);

        for i in 0..hashes_count {
            let slice_start = i * hash_size;
            let slice_end = (i + 1) * hash_size;
            let slice = bytes
                .get(slice_start..slice_end)
                .ok_or_else(Error::vec_to_hash_conversion_error)?;
            let vec =
                Vec::<u8>::try_from(slice).map_err(|_| Error::vec_to_hash_conversion_error())?;
            match T::Hash::try_from(vec) {
                Ok(val) => proof_hashes_slices.push(val),
                Err(_) => return Err(Error::vec_to_hash_conversion_error()),
            }
        }

        Ok(Self::new(proof_hashes_slices))
    }
}
