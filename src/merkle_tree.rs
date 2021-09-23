use crate::{utils, MerkleProof, Hasher};
use crate::utils::indices::get_parent_indices;

pub struct MerkleTree<T> {
    layers: Vec<Vec<Vec<u8>>>,
    hasher: T,
}

fn concat_and_hash<T: Hasher>(left: Option<&Vec<u8>>, right: Option<&Vec<u8>>) -> Vec<u8> {
    let mut concat = left.expect("Left node should always be present, otherwise it's impossible to calculate hash").to_vec();

    match right {
        Some(right_node) => {
            let mut right_node_clone = right_node.to_vec();
            concat.append(&mut right_node_clone);
            T::hash(&concat)
        },
        None => concat
    }
}

impl<T: Hasher> MerkleTree<T> {
    fn calculate_parent_layer(nodes: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let parent_layer_nodes_count = utils::indices::div_ceil(nodes.len(),2);
        let mut layer = Vec::new();

        for i in 0..parent_layer_nodes_count {
            layer.push(concat_and_hash::<T>(nodes.get(i * 2), nodes.get(i * 2 + 1)));
        }

        layer
    }

    fn create_tree(leaf_hashes: Vec<Vec<u8>>) -> Vec<Vec<Vec<u8>>> {
        let tree_depth = utils::indices::get_tree_depth(leaf_hashes.len());
        let mut tree = vec![leaf_hashes];

        for _ in 0..tree_depth {
            // Using unwrap is fine here, since tree always has at least one element
            tree.push(Self::calculate_parent_layer(tree.last().unwrap()));
        }

        tree
    }

    pub fn new(leaf_hashes: Vec<Vec<u8>>, hasher: T) -> Self {
        let layers = Self::create_tree(leaf_hashes);
        Self { layers, hasher }
    }

    pub fn get_root(&self) -> Option<&Vec<u8>> {
        self.layers.last()?.first()
    }

    pub fn get_depth(&self) -> usize {
        return self.layers.len() - 1;
    }

    pub fn get_proof(&self, leaf_indices: &Vec<usize>) -> MerkleProof<T> {
        // Proof consists of all siblings hashes that aren't in the set we're trying to prove
        // 1. Get all sibling indices. Those are the indices we need to get to the root
        // 2. Filter all nodes that doesn't require an additional hash
        // 3. Get all hashes for indices from step 2
        // 4. Remove empty spaces (the leftmost nodes that do not have anything to the right)7

        let mut current_layer_indices = leaf_indices.to_vec();
        let mut proof_hashes: Vec<Vec<u8>> = Vec::new();

        for tree_layer in &self.layers {
            let mut known_nodes = current_layer_indices.to_vec();
            let mut siblings = utils::indices::get_sibling_indices(&current_layer_indices);

            siblings.append(&mut known_nodes);
            siblings.sort();
            siblings.dedup();

            let mut hashes: Vec<Vec<u8>> = siblings
                .iter()
                .map(|index| { tree_layer.get(*index) })
                .filter(|proof_hash| proof_hash.is_some())
                .map(|proof_hash| proof_hash.unwrap().to_vec())
                .collect();

            proof_hashes.append(&mut hashes);
            current_layer_indices = get_parent_indices(&current_layer_indices);
        }

        MerkleProof::new(proof_hashes, &self.hasher)
    }

    pub fn get_layers(&self) -> &Vec<Vec<Vec<u8>>> {
        return &self.layers;
    }

    /**
     * Get tree layers as an array of hex hashes
     *
     * @return {string[][]}
     */
    pub fn get_hex_layers(&self) -> Vec<Vec<String>> {
        self.get_layers()
            .iter()
            .map(|layer| layer.iter().map(utils::collections::to_hex_string).collect())
            .collect()
    }
}
