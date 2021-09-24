use crate::{utils, MerkleProof, Hasher};
use crate::utils::indices::parent_indices;

pub struct MerkleTree<T> {
    layers: Vec<Vec<Vec<u8>>>,
    hasher: T,
}

impl<T: Hasher> MerkleTree<T> {
    fn build_parent_layer(nodes: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let parent_layer_nodes_count = utils::indices::div_ceil(nodes.len(),2);
        (0..parent_layer_nodes_count)
            .map(|i| T::concat_and_hash(nodes.get(i * 2), nodes.get(i * 2 + 1)))
            .collect()
    }

    fn build_tree(leaf_hashes: Vec<Vec<u8>>) -> Vec<Vec<Vec<u8>>> {
        let tree_depth = utils::indices::tree_depth(leaf_hashes.len());
        let mut tree = vec![leaf_hashes];

        for _ in 0..tree_depth {
            // Using unwrap is fine here, since tree always has at least one element
            tree.push(Self::build_parent_layer(tree.last().unwrap()));
        }

        tree
    }

    pub fn new(leaf_hashes: Vec<Vec<u8>>, hasher: T) -> Self {
        let layers = Self::build_tree(leaf_hashes);
        Self { layers, hasher }
    }

    pub fn root(&self) -> Option<&Vec<u8>> {
        self.layers.last()?.first()
    }

    pub fn hex_root(&self) -> Option<String> {
        let root = self.root()?;
        Some(utils::collections::to_hex_string(root))
    }

    pub fn depth(&self) -> usize {
        return self.layers.len() - 1;
    }

    pub fn proof(&self, leaf_indices: &Vec<usize>) -> MerkleProof<T> {
        // Proof consists of all siblings hashes that aren't in the set we're trying to prove
        // 1. Get all sibling indices. Those are the indices we need to get to the root
        // 2. Filter all nodes that doesn't require an additional hash
        // 3. Get all hashes for indices from step 2
        // 4. Remove empty spaces (the leftmost nodes that do not have anything to the right)7

        let mut current_layer_indices = leaf_indices.to_vec();
        let mut proof_hashes: Vec<Vec<u8>> = Vec::new();

        for tree_layer in &self.layers {
            let siblings = utils::indices::sibling_indices(&current_layer_indices);
            let proof_indices = utils::collections::difference(&siblings, &current_layer_indices);

            for index in proof_indices {
                match tree_layer.get(index) {
                    Some(hash) => proof_hashes.push(hash.to_vec()),
                    None => continue,
                }
            }

            current_layer_indices = parent_indices(&current_layer_indices);
        }

        MerkleProof::new(proof_hashes, &self.hasher)
    }

    pub fn layers(&self) -> &Vec<Vec<Vec<u8>>> {
        return &self.layers;
    }

    pub fn hex_layers(&self) -> Vec<Vec<String>> {
        self.layers()
            .iter()
            .map(|layer| layer.iter().map(utils::collections::to_hex_string).collect())
            .collect()
    }
}
