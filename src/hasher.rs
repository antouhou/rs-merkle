use std::convert::TryFrom;
use std::mem;

pub trait Hasher {
    type Hash: Copy + Into<Vec<u8>> + PartialEq + TryFrom<Vec<u8>>;

    fn hash(data: &Vec<u8>) -> Self::Hash;

    fn hash_size() -> usize {
        mem::size_of::<Self::Hash>()
    }

    // This is a default solidity implementation
    fn concat_and_hash(left: Option<&Self::Hash>, right: Option<&Self::Hash>) -> Self::Hash {
        let mut concatenated: Vec<u8> = left.expect("Left node should always be present, otherwise it's impossible to calculate hash").clone().into();

        match right {
            Some(right_node) => {
                let mut right_node_clone: Vec<u8> = right_node.clone().into();
                concatenated.append(&mut right_node_clone);
                Self::hash(&concatenated)
            },
            None => left.unwrap().clone()
        }
    }
}