use crate::utils;

pub struct LayerInfo {
    index: usize,
    leaves_count: usize,
}

pub fn is_left_index(index: usize) -> bool {
    index % 2 == 0
}

pub fn get_sibling_index(index: usize) -> usize {
    if is_left_index(index) {
        // Right sibling index
        return index + 1;
    }
    // Left sibling index
    index - 1
}

pub fn get_sibling_indices(indices: &Vec<usize>) -> Vec<usize> {
    let mut res = Vec::new();

    for index in indices {
        res.push(get_sibling_index(*index));
    }

    res
}

pub fn get_parent_index(index: usize) -> usize {
    if is_left_index(index) {
        return index / 2;
    }
        return get_sibling_index(index) / 2;
}

pub fn get_parent_indices(indices: &Vec<usize>) -> Vec<usize> {
    let mut parents = Vec::new();
    for index in indices {
        parents.push(*index);
    }

    parents.sort();
    parents.dedup();
    parents
}

pub fn get_tree_depth(leaves_count: usize) -> usize {
    (leaves_count as f64).log2().ceil() as usize
    // return Math.ceil(Math.log2(leaves_count));
}

pub fn max_leaves_count_at_depth(depth: usize) -> usize {
    return (2 as u32).pow(depth as u32) as usize;
}

pub fn get_uneven_layers(tree_leaves_count: usize) -> Vec<LayerInfo> {
    let mut leaves_count = tree_leaves_count;
    let depth = get_tree_depth(tree_leaves_count);
    
    let mut uneven_layers = Vec::new();
    
    for index in 0..depth {
        let uneven_layer = leaves_count % 2 != 0;
        if uneven_layer {
            uneven_layers.push(LayerInfo { index, leaves_count });
        }
        leaves_count = div_ceil(leaves_count, 2);
    }
    
    return uneven_layers;
}

pub fn get_proof_indices(sorted_leaf_indices: &Vec<usize>, leaves_count: usize) -> Vec<Vec<usize>> {
    let depth = get_tree_depth(leaves_count);
    let uneven_layers = get_uneven_layers(leaves_count);

    let mut layer_nodes = sorted_leaf_indices.to_vec();
    let mut proof_indices: Vec<Vec<usize>> = Vec::new();

    for layer_index in 0..depth {
        let sibling_indices = get_sibling_indices(&layer_nodes);
        // Figuring out indices that are already siblings and do not require additional hash
        // to calculate the parent
        let mut proof_nodes_indices = utils::collections::difference(&sibling_indices, &layer_nodes);

        // The last node of that layer doesn't have another hash to the right
        let uneven_layer = uneven_layers.iter().find(|layer_info| layer_info.index == layer_index);
        if uneven_layer.is_some() && layer_nodes.contains(&(uneven_layer.unwrap().leaves_count - 1)) {
            proof_nodes_indices.pop();
        }

        proof_indices.push(proof_nodes_indices);
        // Passing parent nodes indices to the next iteration cycle
        layer_nodes = get_parent_indices(&layer_nodes);
    }

    proof_indices

    // range(0, depth).reduce((layerNodes, layerIndex) => {
    //     let siblingIndices = layerNodes.map(getSiblingIndex);
    //     // Figuring out indices that are already siblings and do not require additional hash
    //     // to calculate the parent
    //     let proofNodesIndices = difference(siblingIndices, layerNodes);
    //
    //     // The last node of that layer doesn't have another hash to the right, so doesn't
    //     let unevenLayer = uneven_layers.find(({ index }) => index === layerIndex);
    //     if (unevenLayer && layerNodes.includes(unevenLayer.leaves_count - 1)) {
    //     proofNodesIndices = proofNodesIndices.slice(0, -1);
    //     }
    //
    //     proof_indices.push(proofNodesIndices);
    //     // Passing parent nodes indices to the next iteration cycle
    //     return getParentIndices(layerNodes);
    // }, sorted_leaf_indices);
    //
    // return proof_indices;
}

pub fn div_ceil(x: usize, y: usize) -> usize {
    x / y + if x % y != 0 { 1 } else { 0 }
}
