//! Merkle Trees, also known as Hash Trees, are used to verify that two or more parties have
//! the same data without exchanging the entire data collection.
//!
//! Merkle Trees are used in Git, Mercurial,ZFS, IPFS, Bitcoin, Ethereum, Cassandra and many more.
//! In Git, for example, Merkle Trees are used to find a delta between the local and remote states,
//! and transfer only the delta. In Bitcoin, Merkle Trees are used to verify that a transaction was
//! included into the block without downloading the whole block contents.

pub use hasher::Hasher;
pub use merkle_proof::MerkleProof;
pub use merkle_tree::MerkleTree;

mod merkle_tree;
mod merkle_proof;
mod hasher;

pub mod algorithms;
pub mod error;
mod utils;

