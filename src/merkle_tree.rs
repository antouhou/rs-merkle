use crate::partial_tree::PartialTree;
use crate::utils::indices;
use crate::{utils, Hasher, MerkleProof};

/// [`MerkleTree`] is a Merkle Tree that is well suited for both basic and advanced usage.
///
/// Basic features include creation and verification of merkle proofs from a set of leaves.
/// This is often done in various cryptocurrencies.
///
/// Advanced features include being able to make transactional changes to a tree with
/// being able to roll back to any previous committed state of tree. This scenario is similar
/// to Git and can be found in databases and file systems.
#[derive(Clone)]
pub struct MerkleTree<T: Hasher> {
    current_working_tree: PartialTree<T>,
    history: Vec<PartialTree<T>>,
    uncommitted_leaves: Vec<T::Hash>,
}

impl<T: Hasher> Default for MerkleTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Hasher> MerkleTree<T> {
    /// Creates a new instance of Merkle Tree. Requires specifying the hash algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// use rs_merkle::{MerkleTree, algorithms::Sha256};
    ///
    /// let merkle_tree: MerkleTree<Sha256> = MerkleTree::new();
    ///
    /// let another_merkle_tree = MerkleTree::<Sha256>::new();
    /// ```
    pub fn new() -> Self {
        Self {
            current_working_tree: PartialTree::new(),
            history: Vec::new(),
            uncommitted_leaves: Vec::new(),
        }
    }

    /// Returns the tree root - the top hash of the tree. Used in the inclusion proof verification
    /// function.
    ///
    /// ## Examples
    ///
    pub fn root(&self) -> Option<T::Hash> {
        Some(self.layer_tuples().last()?.first()?.1)
    }

    /// Clones leave hashes and build the tree from them
    pub fn from_leaves(leaves: &[T::Hash]) -> Self {
        let mut tree = Self::new();

        tree.append(leaves.to_vec().as_mut());
        tree.commit();

        tree
    }

    /// Returns Merkle tree root serialized as a hex string
    pub fn root_hex(&self) -> Option<String> {
        let root = self.root()?;
        Some(utils::collections::to_hex_string(&root))
    }

    /// Returns tree depth. Tree depth is how many layers there is between
    /// leaves and root
    ///
    /// ## Examples
    ///
    pub fn depth(&self) -> usize {
        self.layer_tuples().len() - 1
    }

    /// Returns helper nodes required to build a partial tree for the given indices
    /// to be able to extract a root from it. Useful in constructing merkle proofs
    fn helper_nodes(&self, leaf_indices: &[usize]) -> Vec<T::Hash> {
        let mut helper_nodes = Vec::<T::Hash>::new();

        for layer in self.helper_node_tuples(leaf_indices) {
            for (_index, hash) in layer {
                helper_nodes.push(hash)
            }
        }

        helper_nodes
    }

    /// Gets all helper nodes required to build a partial merkle tree for the given indices,
    /// cloning all required hashes into the resulting vector.
    fn helper_node_tuples(&self, leaf_indices: &[usize]) -> Vec<Vec<(usize, T::Hash)>> {
        let mut current_layer_indices = leaf_indices.to_vec();
        let mut helper_nodes: Vec<Vec<(usize, T::Hash)>> = Vec::new();

        for tree_layer in self.layers() {
            let mut helpers_layer = Vec::new();
            let siblings = utils::indices::sibling_indices(&current_layer_indices);
            // Filter all nodes that do not require an additional hash to be calculated
            let helper_indices = utils::collections::difference(&siblings, &current_layer_indices);

            for index in helper_indices {
                if let Some(hash) = tree_layer.get(index) {
                    helpers_layer.push((index, hash.clone()));
                }
            }

            helper_nodes.push(helpers_layer);
            current_layer_indices = indices::parent_indices(&current_layer_indices);
        }

        helper_nodes
    }

    /// Returns merkle proof required to prove inclusion of items in a data set.
    ///
    /// ## Examples
    ///
    /// ```
    /// # use rs_merkle::{MerkleTree, MerkleProof, algorithms::Sha256, Hasher, Error, utils};
    /// # use std::convert::TryFrom;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let leaf_values = ["a", "b", "c", "d", "e", "f"];
    /// let leaves: Vec<[u8; 32]> = leaf_values
    ///     .iter()
    ///     .map(|x| Sha256::hash(x.as_bytes()))
    ///     .collect();
    ///
    /// let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    /// let indices_to_prove = vec![3, 4];
    /// let leaves_to_prove = leaves.get(3..5).ok_or("can't get leaves to prove")?;
    /// let merkle_proof = merkle_tree.proof(&indices_to_prove);
    /// let merkle_root = merkle_tree.root().ok_or("couldn't get the merkle root")?;
    /// // Serialize proof to pass it to the client
    /// let proof_bytes = merkle_proof.to_bytes();
    ///
    /// // Parse proof back on the client
    /// let proof = MerkleProof::<Sha256>::try_from(proof_bytes)?;
    ///
    /// assert_eq!(proof.verify(merkle_root, &indices_to_prove, leaves_to_prove, leaves.len()), true);
    /// # Ok(())
    /// # }
    /// ```
    ///
    pub fn proof(&self, leaf_indices: &[usize]) -> MerkleProof<T> {
        MerkleProof::<T>::new(self.helper_nodes(leaf_indices))
    }

    /// Returns a slice of tree leaves, i.e. the slice of all the hashes that comprise the
    /// base level of the tree.
    ///
    /// ## Examples
    ///
    pub fn leaves(&self) -> Option<Vec<T::Hash>> {
        Some(self.layers().first()?.iter().cloned().collect())
    }

    pub fn leaves_tuples(&self) -> Option<&[(usize, T::Hash)]> {
        Some(&self.layer_tuples().first()?)
    }

    /// Returns the number of leaves in the tree
    pub fn leaves_len(&self) -> usize {
        if let Some(leaves) = self.layer_tuples().first() {
            return leaves.len();
        }

        0
    }

    /// Returns the whole tree, where the first layer is leaves and
    /// consequent layers are nodes.
    pub fn layers(&self) -> Vec<Vec<T::Hash>> {
        self.current_working_tree.layer_nodes()
    }

    pub fn layer_tuples(&self) -> &[Vec<(usize, T::Hash)>] {
        self.current_working_tree.layers()
    }

    /// Same as [`layers`](MerkleTree::layers), but serializes each hash as a hex string
    pub fn layers_hex(&self) -> Vec<Vec<String>> {
        self.layer_tuples()
            .iter()
            .map(|layer| {
                layer
                    .iter()
                    .map(|(_, hash)| utils::collections::to_hex_string(hash))
                    .collect()
            })
            .collect()
    }

    /// Inserts a new leaf. Please note it won't modify the root just yet; For the changes
    /// to be applied to the root, [`commit`](MerkleTree::commit) method should be called first. To get the root
    /// of the new tree without applying the changes, you can use [`uncommitted_root`](MerkleTree::uncommitted_root)
    ///
    /// # Example
    /// // TODO
    pub fn insert(&mut self, leaf: T::Hash) -> &mut Self {
        self.uncommitted_leaves.push(leaf);
        self
    }

    /// Appends leaves to the tree. Behaves similarly to [`commit`](MerkleTree::commit), but for a list of items.
    /// Takes ownership of the elements of the [`std::vec::Vec<T>`], similarly to [`append`](std::vec::Vec::append) of a [`std::vec::Vec<T>`]
    pub fn append(&mut self, leaves: &mut Vec<T::Hash>) -> &mut Self {
        self.uncommitted_leaves.append(leaves);
        self
    }

    /// Calculates the root of the uncommitted changes as if they were committed.
    /// Will return the same hash as [`root`](MerkleTree::root) after [`commit`](MerkleTree::commit)
    pub fn uncommitted_root(&self) -> Option<T::Hash> {
        let shadow_tree = self.uncommitted_diff()?;
        shadow_tree.root().cloned()
    }

    /// Same as `uncommitted_root`, but serialized to a hex string
    pub fn uncommitted_root_hex(&self) -> Option<String> {
        let root = self.uncommitted_root()?;
        Some(utils::collections::to_hex_string(&root))
    }

    /// Commits changes made by [`insert`](MerkleTree::insert) and [`append`](MerkleTree::append)
    /// and modifies the root.
    /// Commits changes to the history, so the tree can be rolled back to any previous commit.
    pub fn commit(&mut self) {
        if let Some(diff) = self.uncommitted_diff() {
            self.history.push(diff.clone());
            self.current_working_tree.merge_unverified(diff);
            self.uncommitted_leaves.clear();
        }
    }

    /// Aborts all uncommitted [`insert`](MerkleTree::insert) and [`append`](MerkleTree::append)
    /// operations without applying them to the tree.
    pub fn abort_uncommitted(&mut self) {
        self.uncommitted_leaves.clear()
    }

    /// Rolls back one commit and reverts tree to the previous state.
    /// Removes the latest commit from the changes history
    pub fn rollback(&mut self) {
        // Remove the most recent commit
        self.history.pop();
        // Clear working tree
        self.current_working_tree.clear();
        // Applying all the commits up to the removed one. This is not an
        // efficient way of doing things, but the diff subtraction is not implemented yet on
        // PartialMerkleTree
        for commit in &self.history {
            self.current_working_tree.merge_unverified(commit.clone());
        }
    }

    /// Creates a diff from a changes that weren't committed to the main tree yet. Can be used
    /// to get uncommitted root or can be merged with the main tree
    fn uncommitted_diff(&self) -> Option<PartialTree<T>> {
        if self.uncommitted_leaves.is_empty() {
            return None;
        }

        let mut committed_leaves_count = self.leaves_len();

        let shadow_indices: Vec<usize> = self
            .uncommitted_leaves
            .iter()
            .enumerate()
            .map(|(index, _)| committed_leaves_count + index)
            .collect();
        // Tuples (index, hash) needed to construct a partial tree, since partial tree can't
        // maintain indices otherwise
        let mut shadow_node_tuples: Vec<(usize, T::Hash)> = shadow_indices
            .iter()
            .cloned()
            .zip(self.uncommitted_leaves.iter().cloned())
            .collect();
        let mut partial_tree_tuples = self.helper_node_tuples(&shadow_indices);

        // Figuring what tree height would be if we've committed the changes
        let mut leaves_in_new_tree = self.leaves_len() + self.uncommitted_leaves.len();
        let uncommitted_tree_depth = utils::indices::tree_depth(leaves_in_new_tree);

        match partial_tree_tuples.first_mut() {
            Some(first_layer) => {
                first_layer.append(&mut shadow_node_tuples);
                first_layer.sort_by(|(a, _), (b, _)| a.cmp(b));
            }
            None => partial_tree_tuples.push(shadow_node_tuples),
        }

        // Building a partial tree with the changes that would be needed to the working tree
        PartialTree::<T>::build(partial_tree_tuples, uncommitted_tree_depth).ok()
    }
}
