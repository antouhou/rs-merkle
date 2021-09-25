use crate::{utils, MerkleProof, Hasher};
use crate::utils::indices::parent_indices;

#[derive(Clone)]
pub struct MerkleTree<T: Hasher> {
    layers: Vec<Vec<T::Hash>>,
}

impl<T: Hasher> MerkleTree<T> {
    fn build_parent_layer(nodes: &Vec<T::Hash>) -> Vec<T::Hash> {
        let parent_layer_nodes_count = utils::indices::div_ceil(nodes.len(),2);
        (0..parent_layer_nodes_count)
            .map(|i| T::concat_and_hash(nodes.get(i * 2), nodes.get(i * 2 + 1)))
            .collect()
    }

    fn build_tree(leaves: &Vec<T::Hash>) -> Vec<Vec<T::Hash>> {
        let tree_depth = utils::indices::tree_depth(leaves.len());
        let mut tree: Vec<Vec<T::Hash>> = vec![leaves.clone()];

        for _ in 0..tree_depth {
            // Using unwrap is fine here, since tree always has at least one element
            tree.push(Self::build_parent_layer(tree.last().unwrap()));
        }

        tree
    }

    pub fn new(leaves: &Vec<T::Hash>) -> Self {
        let layers = Self::build_tree(leaves);
        Self { layers }
    }

    pub fn root(&self) -> Option<&T::Hash> {
        self.layers.last()?.first()
    }

    pub fn hex_root(&self) -> Option<String> {
        let root = self.root()?;
        Some(utils::collections::to_hex_string(root))
    }

    /// Returns tree depth. Tree depth is how many layers there is between
    /// leaves and root
    pub fn depth(&self) -> usize {
        self.layers.len() - 1
    }

    /// Proof consists of all siblings hashes that aren't in the set we're trying to prove
    ///
    /// # Implementation
    ///
    /// 1. Get all sibling indices. Those are the indices we need to get to the root
    /// 2. Filter all nodes that doesn't require an additional hash
    /// 3. Get all hashes for indices from step 2
    /// 4. Remove empty spaces (the leftmost nodes that do not have anything to the right)
    pub fn proof(&self, leaf_indices: &Vec<usize>) -> MerkleProof<T> {
        let mut current_layer_indices = leaf_indices.to_vec();
        let mut proof_hashes: Vec<T::Hash> = Vec::new();

        for tree_layer in &self.layers {
            let siblings = utils::indices::sibling_indices(&current_layer_indices);
            let proof_indices = utils::collections::difference(&siblings, &current_layer_indices);

            for index in proof_indices {
                match tree_layer.get(index) {
                    Some(hash) => {
                        proof_hashes.push(hash.clone());
                    },
                    None => continue,
                }
            }

            current_layer_indices = parent_indices(&current_layer_indices);
        }

        let proof: MerkleProof<T> = MerkleProof::<T>::new(proof_hashes);
        proof
    }

    pub fn leaves(&self) -> Option<&Vec<T::Hash>> {
        self.layers().first()
    }

    pub fn layers(&self) -> &Vec<Vec<T::Hash>> {
        &self.layers
    }

    pub fn hex_layers(&self) -> Vec<Vec<String>> {
        self.layers()
            .iter()
            .map(|layer| layer.iter().map(utils::collections::to_hex_string).collect())
            .collect()
    }
}
