//! This module contains built-in implementations of `rs_merkle::Hasher`
mod sha256;

pub use sha256::Sha256Algorithm as Sha256;
