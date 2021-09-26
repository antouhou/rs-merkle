use crate::{utils, MerkleProof, Hasher};
use crate::utils::indices::{parent_indices, proof_indices};
use crate::partial_tree::PartialTree;

/// `MerkleTree`
#[derive(Clone)]
pub struct MerkleTree<T: Hasher> {
    //layers: Vec<Vec<T::Hash>>,
    inner_tree: PartialTree<T>,
    shadow_leaves: Vec<T::Hash>
}

impl<T: Hasher> MerkleTree<T> {
    /// Takes leaves (item hashes) as an argument and build a Merkle Tree from them
    pub fn new(leaves: &Vec<T::Hash>) -> Self {
        // let layers = Self::build_tree(leaves);
        // Partial tree can't panic when constructed from leaves, since
        // the panic in the tree construction is related to having not enough
        // helper nodes, and helper nodes are not used in this case.
        let partial_tree = PartialTree::from_leaves(leaves).unwrap();
        Self { shadow_leaves: Vec::new(), inner_tree: partial_tree }
    }

    /// Returns Merkle tree root
    pub fn root(&self) -> Option<T::Hash> {
        self.layers().last()?.first().cloned()
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
        self.inner_tree.layer_nodes()
    }

    /// Same as `layers`, but serializes each hash as a hex string
    pub fn layers_hex(&self) -> Vec<Vec<String>> {
        self.layers()
            .iter()
            .map(|layer| layer.iter().map(utils::collections::to_hex_string).collect())
            .collect()
    }

    /// Inserts a new leaf. Please note it won't modify the root just yet; For the changes
    /// to be applied to the root, `.commit()` method should be called first. To get the root
    /// of the new tree without applying the changes, you can use `.uncommitted_root`
    ///
    /// # Example
    /// // TODO
    pub fn insert(&mut self, leaf: T::Hash) {
        self.shadow_leaves.push(leaf)
    }

    /// Appends leaves to the tree. Behaves similarly to `commit`, but for a list of items.
    /// Takes ownership of the elements of the `Vec<T>`, similarly to `append` of a `Vec<T>`
    pub fn append(&mut self, leaves: &mut Vec<T::Hash>) {
        self.shadow_leaves.append(leaves)
    }

    /// Calculates the root of the uncommitted changes as if they were committed
    pub fn uncommitted_root(&self) -> Option<T::Hash> {
        let shadow_tree = self.uncommitted_diff()?;
        shadow_tree.root().cloned()
    }

    /// Same as `uncommitted_root`, but serialized to a hex string
    pub fn uncommitted_root_hex(&self) -> Option<String> {
        let root = self.uncommitted_root()?;
        Some(utils::collections::to_hex_string(&root))
    }

    /// Creates a diff from a changes that weren't committed to the main tree yet. Can be used
    /// to get uncommitted root or can be merged with the main tree
    fn uncommitted_diff(&self) -> Option<PartialTree<T>> {
        let shadow_indices: Vec<usize> = self.shadow_leaves.iter().enumerate().map(|(index, _)| index).collect();
        // Tuples (index, hash) needed to construct a partial tree, since partial tree can't
        // maintain indices otherwise
        let shadow_node_tuples: Vec<(usize, T::Hash)> = shadow_indices.iter().cloned().zip(self.shadow_leaves.iter().cloned()).collect();
        let helper_node_tuples = self.helper_node_tuples(&shadow_indices);

        // Figuring what tree height would be if we've committed the changes
        let mut leaves_in_new_tree = self.shadow_leaves.len();
        if let Some(committed_leaves) = self.leaves() {
            leaves_in_new_tree += committed_leaves.len();
        }
        let uncommitted_tree_depth = utils::indices::tree_depth(leaves_in_new_tree);

        // Building a partial tree with the changes that would be needed to committed tree
        PartialTree::<T>::new(&shadow_node_tuples, &helper_node_tuples, uncommitted_tree_depth).ok()
    }

    /// Commits changes made by `insert` and `append` and modifies the root by rebuilding the tree
    pub fn commit(&mut self) {
        if let Some(diff) = self.uncommitted_diff() {
            self.inner_tree.merge_unverified(diff);
        }
    }

    /// Aborts all uncommitted `insert` and `append` operations without applying them to the tree.
    pub fn rollback(&mut self) {
        self.shadow_leaves.clear()
    }
}
