#[cfg(feature = "keccak256")]
use crate::{prelude::*, Hasher};

#[cfg(feature = "keccak256")]
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

#[cfg(feature = "keccak256")]
#[derive(Clone)]
pub struct Keccak256Algorithm {}

#[cfg(feature = "keccak256")]
impl Hasher for Keccak256Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut output);
        output
    }
}
