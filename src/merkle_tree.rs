use crate::{utils, MerkleProof, Hasher};
use crate::utils::indices::{parent_indices, proof_indices_by_layers};
use crate::partial_tree::PartialTree;

/// [`MerkleTree`] is a Merkle Tree that is well suited for both basic and advanced usage.
///
/// Basic features include creation and verification of merkle proofs from a set of leaves.
/// This is often done in various cryptocurrencies.
///
/// Advanced features include being able to make transactional changes to a tree with
/// being able to roll back to any previous committed state of tree. This scenario is similar
/// to Git and can be found in databases and file systems.
///
/// # Examples
///
/// ## Basic usage for cryptocurrency proofs:
///
/// ```
/// use rs_merkle::{MerkleTree, algorithms::Sha256, Hasher};
///
/// let leaf_values = ["a", "b", "c", "d", "e", "f"];
/// let expected_root_hex = "1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2";
/// let leaves = leaf_values
///         .iter()
///         .map(|x| Sha256::hash(x.as_bytes().to_vec().as_ref()))
///         .collect();
///
/// let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
/// let hex_root = merkle_tree.root_hex().unwrap();
///
/// assert_eq!(hex_root, expected_root_hex);
///
/// let indices_to_prove = vec![3, 4];
/// let merkle_proof = merkle_tree.proof(&indices_to_prove);
/// ```
///
/// ## Advanced usage with rolling several commits back
///
/// ```
/// use rs_merkle::{MerkleTree, algorithms::Sha256, Hasher};
///
/// let leaf_values = ["a", "b", "c", "d", "e", "f"];
/// let expected_root_hex = "1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2";
/// let leaves: Vec<[u8; 32]> = leaf_values
/// .iter()
/// .map(|x| Sha256::hash(x.as_bytes().to_vec().as_ref()))
/// .collect();
///
/// let mut merkle_tree: MerkleTree<Sha256> = MerkleTree::new();
/// merkle_tree.append(leaves.clone().as_mut());
/// // No changes were committed just yet, tree is empty
/// assert_eq!(merkle_tree.root(), None);
///
/// merkle_tree.commit();
///
/// assert_eq!(merkle_tree.uncommitted_root_hex().unwrap(), String::from("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2"));
///
/// // Adding a new leaf
/// merkle_tree.insert(Sha256::hash("g".as_bytes().to_vec().as_ref()));
///
/// // Uncommitted root must reflect the insert
/// assert_eq!(merkle_tree.uncommitted_root_hex().unwrap(), String::from("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034"));
///
/// merkle_tree.commit();
///
/// // After calling commit, uncommitted root will become committed
/// assert_eq!(merkle_tree.root_hex().unwrap(), String::from("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034"));
///
/// // Adding some more leaves
/// merkle_tree.append(vec![
///     Sha256::hash("h".as_bytes().to_vec().as_ref()),
///     Sha256::hash("k".as_bytes().to_vec().as_ref()),
/// ].as_mut());
///
/// // Checking that the uncommitted root has changed, but the committed one hasn't
/// assert_eq!(merkle_tree.uncommitted_root_hex().unwrap(), String::from("09b6890b23e32e607f0e5f670ab224e36af8f6599cbe88b468f4b0f761802dd6"));
/// assert_eq!(merkle_tree.root_hex().unwrap(), String::from("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034"));
///
/// merkle_tree.commit();
///
/// // Checking committed changes again
/// assert_eq!(merkle_tree.root_hex().unwrap(), String::from("09b6890b23e32e607f0e5f670ab224e36af8f6599cbe88b468f4b0f761802dd6"));
///
/// merkle_tree.rollback();
///
/// // Check that we rolled one commit back
/// assert_eq!(merkle_tree.root_hex().unwrap(), String::from("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034"));
///
/// merkle_tree.rollback();
///
/// // Rolling back to the state after the very first commit
/// assert_eq!(merkle_tree.root_hex().unwrap(), expected_root_hex);
/// ```
#[derive(Clone)]
pub struct MerkleTree<T: Hasher> {
    current_working_tree: PartialTree<T>,
    history: Vec<PartialTree<T>>,
    uncommitted_leaves: Vec<T::Hash>,
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

    /// Returns Merkle tree root
    pub fn root(&self) -> Option<T::Hash> {
        self.layers().last()?.first().cloned()
    }

    /// Clones leave hashes and build the tree from them
    pub fn from_leaves(leaves: &Vec<T::Hash>) -> Self {
        let mut tree = Self::new();

        tree.append(leaves.clone().as_mut());
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
    pub fn depth(&self) -> usize {
        self.layers().len() - 1
    }

    /// Returns helper nodes required to build a partial tree for the given indices
    /// to be able to extract a root from it. Useful in constructing merkle proofs
    fn helper_nodes(&self, leaf_indices: &Vec<usize>) -> Vec<T::Hash> {
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
    fn helper_node_tuples(&self, leaf_indices: &Vec<usize>) -> Vec<Vec<(usize, T::Hash)>> {
        let mut current_layer_indices = leaf_indices.to_vec();
        let mut helper_nodes: Vec<Vec<(usize, T::Hash)>> = Vec::new();

        for tree_layer in self.layers() {
            let mut helpers_layer = Vec::new();
            let siblings = utils::indices::sibling_indices(&current_layer_indices);
            // Filter all nodes that do not require an additional hash to be calculated
            let helper_indices = utils::collections::difference(&siblings, &current_layer_indices);

            for index in helper_indices {
                match tree_layer.get(index) {
                    Some(hash) => {
                        helpers_layer.push((index, hash.clone()));
                    },
                    // This means that there's no right sibling to the current index, thus
                    // we don't need to include anything in the proof for that index
                    None => continue,
                }
            }

            helper_nodes.push(helpers_layer);
            current_layer_indices = parent_indices(&current_layer_indices);
        }

        helper_nodes
    }

    /// Returns merkle proof required to prove inclusion of items at given indices
    pub fn proof(&self, leaf_indices: &Vec<usize>) -> MerkleProof<T> {
        MerkleProof::<T>::new(self.helper_nodes(leaf_indices))
    }

    /// Returns tree leaves, i.e. the bottom level
    pub fn leaves(&self) -> Option<Vec<T::Hash>> {
        self.layers().first().cloned()
    }

    /// Returns the whole tree, where the first layer is leaves and
    /// consequent layers are nodes.
    pub fn layers(&self) -> Vec<Vec<T::Hash>> {
        self.current_working_tree.layer_nodes()
    }

    /// Same as [`layers`](MerkleTree::layers), but serializes each hash as a hex string
    pub fn layers_hex(&self) -> Vec<Vec<String>> {
        self.layers()
            .iter()
            .map(|layer| layer.iter().map(utils::collections::to_hex_string).collect())
            .collect()
    }

    /// Inserts a new leaf. Please note it won't modify the root just yet; For the changes
    /// to be applied to the root, [`commit`](MerkleTree::commit) method should be called first. To get the root
    /// of the new tree without applying the changes, you can use [`uncommitted_root`](MerkleTree::uncommitted_root)
    ///
    /// # Example
    /// // TODO
    pub fn insert(&mut self, leaf: T::Hash) {
        self.uncommitted_leaves.push(leaf)
    }

    /// Appends leaves to the tree. Behaves similarly to [`commit`](MerkleTree::commit), but for a list of items.
    /// Takes ownership of the elements of the [`std::vec::Vec<T>`], similarly to [`append`](std::vec::Vec::append) of a [`std::vec::Vec<T>`]
    pub fn append(&mut self, leaves: &mut Vec<T::Hash>) {
        self.uncommitted_leaves.append(leaves)
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
        let shadow_indices: Vec<usize> = self.uncommitted_leaves.iter().enumerate().map(|(index, _)| index).collect();
        // Tuples (index, hash) needed to construct a partial tree, since partial tree can't
        // maintain indices otherwise
        let mut shadow_node_tuples: Vec<(usize, T::Hash)> = shadow_indices.iter().cloned().zip(self.uncommitted_leaves.iter().cloned()).collect();
        let mut partial_tree_tuples = self.helper_node_tuples(&shadow_indices);

        // Figuring what tree height would be if we've committed the changes
        let mut leaves_in_new_tree = self.uncommitted_leaves.len();
        if let Some(committed_leaves) = self.leaves() {
            leaves_in_new_tree += committed_leaves.len();
        }
        let uncommitted_tree_depth = utils::indices::tree_depth(leaves_in_new_tree);

        match partial_tree_tuples.first_mut() {
            Some(first_layer) => {
                first_layer.append(&mut shadow_node_tuples);
                first_layer.sort_by(|(a, _), (b, _)| a.cmp(b));
            },
            None => partial_tree_tuples.push(shadow_node_tuples)
        }

        // Building a partial tree with the changes that would be needed to the working tree
        PartialTree::<T>::build(partial_tree_tuples, uncommitted_tree_depth).ok()
    }
}
