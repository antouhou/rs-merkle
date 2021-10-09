use crate::Hasher;
use sha2::{digest::FixedOutput, Digest, Sha256};

/// Sha256 implementation of the `rs_merkle::Hasher` trait
#[derive(Clone)]
pub struct Sha256Algorithm {}

impl Hasher for Sha256Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(data);
        <[u8; 32]>::from(hasher.finalize_fixed())
    }
}
