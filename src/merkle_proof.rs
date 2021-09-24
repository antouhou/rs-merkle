use crate::{Hasher, utils};

pub struct MerkleProof<T> {
    proof_hashes: Vec<Vec<u8>>,
    hasher: T
}

impl<T: Hasher> MerkleProof<T> {
    pub fn new(proof_hashes: Vec<Vec<u8>>, hasher: &T) -> Self {
        MerkleProof {
            proof_hashes, hasher: hasher.clone()
        }
    }

    pub fn proof_hashes(&self) -> &Vec<Vec<u8>> {
        &self.proof_hashes
    }

    pub fn hex_proof_hashes(&self) -> Vec<String> {
        self.proof_hashes
            .iter()
            .map(utils::collections::to_hex_string)
            .collect()
    }

    pub fn root(&self, leaf_indices: &Vec<usize>, leaf_hashes: &Vec<Vec<u8>>, total_leaves_count: usize) -> Vec<u8> {
        let mut leaf_tuples: Vec<(usize, Vec<u8>)> = leaf_indices.iter().cloned().zip(leaf_hashes.iter().cloned()).collect();
        leaf_tuples.sort_by(|(a, _), (b, _)| a.cmp(b));
        let proof_indices = utils::indices::proof_indices(leaf_indices, total_leaves_count);

        let mut proof_tuples_by_layers: Vec<Vec<(usize, Vec<u8>)>> = Vec::new();

        let mut next_slice_start = 0;
        for indices in proof_indices {
            let slice_start = next_slice_start;
            next_slice_start += indices.len();

            let hashes = self.proof_hashes.get(slice_start..next_slice_start).unwrap().to_vec();
            proof_tuples_by_layers.push(indices.iter().cloned().zip(hashes.iter().cloned()).collect());
        }

        let mut tree = vec![leaf_tuples];

        for layerIndex in 0..proof_tuples_by_layers.len() {
            let mut proofs = proof_tuples_by_layers.get(layerIndex).unwrap().clone();
            //println!("Proofs: {:?}", proofs.iter().cloned().map());
            let mut nodes = tree.get(layerIndex).unwrap().clone();
            let known_indices: Vec<usize> = nodes.iter().cloned().map(|(index, _)| index).collect();
            proofs.append(&mut nodes);
            proofs.sort_by(|(a, _), (b, _)| a.cmp(b));
            let current_layer: Vec<Vec<u8>> = proofs.iter().cloned().map(|(_, hash)| hash).collect();


            let parent_indices = utils::indices::parent_indices(&known_indices);

            let parent_layer = parent_indices
                .iter()
                .cloned()
                .enumerate()
                .map(|(i, parent_node_index)| (
                    parent_node_index,
                    T::concat_and_hash(
                        current_layer.get(i * 2),
                        current_layer.get(i * 2 + 1)
                    ))
                )
                .collect();

            tree.push(parent_layer);
        }

        return tree.last().unwrap().first().unwrap().1.clone();
    }

    pub fn hex_root(&self, leaf_indices: &Vec<usize>, leaf_hashes: &Vec<Vec<u8>>, total_leaves_count: usize) -> String {
        let root = self.root(leaf_indices, leaf_hashes, total_leaves_count);
        utils::collections::to_hex_string(&root)
    }
}