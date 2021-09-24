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

pub fn sibling_indices(indices: &Vec<usize>) -> Vec<usize> {
    indices.iter().cloned().map(get_sibling_index).collect()
}

pub fn parent_index(index: usize) -> usize {
    if is_left_index(index) {
        return index / 2;
    }
        return get_sibling_index(index) / 2;
}

pub fn parent_indices(indices: &Vec<usize>) -> Vec<usize> {
    let mut parents: Vec<usize> = indices.iter().cloned().map(parent_index).collect();
    parents.dedup();
    parents
}

pub fn tree_depth(leaves_count: usize) -> usize {
    (leaves_count as f64).log2().ceil() as usize
}

pub fn max_leaves_count_at_depth(depth: usize) -> usize {
    return (2 as u32).pow(depth as u32) as usize;
}

pub fn uneven_layers(tree_leaves_count: usize) -> Vec<LayerInfo> {
    let mut leaves_count = tree_leaves_count;
    let depth = tree_depth(tree_leaves_count);
    
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

pub fn proof_indices(sorted_leaf_indices: &Vec<usize>, leaves_count: usize) -> Vec<Vec<usize>> {
    let depth = tree_depth(leaves_count);
    let uneven_layers = uneven_layers(leaves_count);

    let mut layer_nodes = sorted_leaf_indices.to_vec();
    let mut proof_indices: Vec<Vec<usize>> = Vec::new();

    for layer_index in 0..depth {
        let sibling_indices = sibling_indices(&layer_nodes);
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
        layer_nodes = parent_indices(&layer_nodes);
    }

    proof_indices
}

pub fn div_ceil(x: usize, y: usize) -> usize {
    x / y + if x % y != 0 { 1 } else { 0 }
}
