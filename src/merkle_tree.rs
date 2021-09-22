struct ProofAccumulator {
    current_layer_indices: number[],
    proof_hashes: Uint8Array[]
}

pub struct  MerkleTree {
    layers: Vec<Vec<Vec<u8>>>
    // hash_function: (i: Uint8Array) => Uint8Array;
}

fn concat_and_hash(left: Option<&Vec<u8>>, right: Option<&Vec<u8>>) -> Vec<u8> {
    // TODO: implement and add hash function
    Vec::new()
}

fn get_tree_depth(tree_size: usize) -> u32 {
    // TODO: implement
    return 1;
}

impl MerkleTree {
    fn calculate_parent_layer(&self, nodes: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let parent_layer_nodes_count = Math.ceil(nodes.length / 2);
        let mut layer = Vec::new();

        for i in 0..parent_layer_nodes_count {
            layer.push(concat_and_hash(nodes.get(i * 2), nodes.get(i * 2 + 1)));
        }

        layer
    }

    fn create_tree(&self, leaf_hashes: Vec<Vec<u8>>) -> Vec<Vec<Vec<u8>>> {
        let tree_depth = get_tree_depth(leaf_hashes.len());
        let range = 0..tree_depth;
        let mut tree = vec![leaf_hashes];
        range.fold(&mut tree, |&mut tre, layer_index| tre.push(&self.calculate_parent_layer(tree.get(layer_index))));
        tree
    }

    pub fn new(leafHashes: Uint8Array[], hashFunction: (i: Uint8Array) => Uint8Array) {
        this.hashFunction = hashFunction;
        this.layers = this.createTree(leafHashes);
    }

// Public methods

    pub fn get_root(): Uint8Array {
    return this.layers[this.layers.length - 1][0];
    }

    pub fn get_depth(): number {
    return this.layers.length - 1;
    }

    pub fn get_proof(leafIndices: number[]): MerkleProof {
// Proof consists of all siblings hashes that aren't in the set we're trying to prove
// 1. Get all sibling indices. Those are the indices we need to get to the root
// 2. Filter all nodes that doesn't require an additional hash
// 3. Get all hashes for indices from step 2
// 4. Remove empty spaces (the leftmost nodes that do not have anything to the right)7
    const { proofHashes: proof } = this.layers.reduce((
{ currentLayerIndices, proofHashes }: ProofAccumulator, treeLayer,
) => ({
currentLayerIndices: getParentIndices(currentLayerIndices),
proofHashes: [
...proofHashes,
...currentLayerIndices
.map(getSiblingIndex)
.filter((siblingIndex) => !currentLayerIndices.includes(siblingIndex))
.map((index) => treeLayer[index])
.filter((proofHash) => !!proofHash)],
}),
{
currentLayerIndices: leafIndices,
proofHashes: [],
});

return new MerkleProof(proof, this.hashFunction);
}

getLayers(): Uint8Array[][] {
return this.layers;
}

/**
 * Get tree layers as an array of hex hashes
 *
 * @return {string[][]}
 */
pub fn get_hex_layers(): string[][] {
return this.getLayers().map((layer) => layer.map(uint8ArrayToHex));
}
}
}
