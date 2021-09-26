use sha2::{Sha256, Digest, digest::FixedOutput};
use crate::Hasher;

/// Sha256 implementation of the `rs_merkle::Hasher` trait
#[derive(Clone)]
pub struct Sha256Algorithm {}

impl Hasher for Sha256Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &Vec<u8>) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(data);
        <[u8; 32]>::from(hasher.finalize_fixed())
    }
}