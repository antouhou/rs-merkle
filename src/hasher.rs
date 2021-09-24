pub trait Hasher: Clone {
    fn hash(data: &Vec<u8>) -> Vec<u8>;

    // This is a default solidity implementation
    fn concat_and_hash(left: Option<&Vec<u8>>, right: Option<&Vec<u8>>) -> Vec<u8> {
        let mut concatenated = left.expect("Left node should always be present, otherwise it's impossible to calculate hash").to_vec();

        match right {
            Some(right_node) => {
                let mut right_node_clone = right_node.to_vec();
                concatenated.append(&mut right_node_clone);
                Self::hash(&concatenated)
            },
            None => concatenated
        }
    }
}