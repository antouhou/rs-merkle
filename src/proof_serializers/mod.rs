//! This module contains built-in implementations of the [`MerkleProofSerializer`] trait.
//! Serializers are used in [`MerkleProof::serialize`] and [`MerkleProof::deserialize`]
//!
//! [`MerkleProofSerializer`]: crate::MerkleProofSerializer
//! [`MerkleProof::serialize`]: crate::MerkleProof::serialize
//! [`MerkleProof::deserialize`]: crate::MerkleProof::deserialize

mod direct_hashes_order;
mod reverse_hashes_order;

pub use direct_hashes_order::DirectHashesOrder;
pub use reverse_hashes_order::ReverseHashesOrder;