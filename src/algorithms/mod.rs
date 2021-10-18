//! This module contains built-in implementations of the [`Hasher`]
//!
//! [`Hasher`]: crate::Hasher
mod sha256;

pub use sha256::Sha256Algorithm as Sha256;
