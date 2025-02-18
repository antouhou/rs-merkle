//! This module contains built-in implementations of the [`Hasher`]
//!
//! [`Hasher`]: crate::Hasher
mod keccak256;
mod sha256;
mod sha384;

pub use keccak256::Keccak256Algorithm as Keccak256;
pub use sha256::Sha256Algorithm as Sha256;
pub use sha384::Sha384Algorithm as Sha384;
