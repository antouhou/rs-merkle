pub trait Hasher: Clone {
    fn hash(data: &Vec<u8>) -> Vec<u8>;
}