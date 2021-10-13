//! Merkle Trees, also known as Hash Trees, are used to verify that two or more parties have
//! the same data without exchanging the entire data collection.
//!
//! Merkle Trees are used in Git, Mercurial,ZFS, IPFS, Bitcoin, Ethereum, Cassandra and many more.
//! In Git, for example, Merkle Trees are used to find a delta between the local and remote states,
//! and transfer only the delta. In Bitcoin, Merkle Trees are used to verify that a transaction was
//! included into the block without downloading the whole block contents.
//!
//! ## Examples
//!
//! Basic usage for verifying Merkle proofs:
//!
//! ```
//! # use rs_merkle::{MerkleTree, MerkleProof, algorithms::Sha256, Hasher, Error, utils};
//! # use std::convert::TryFrom;
//! #
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let leaf_values = ["a", "b", "c", "d", "e", "f"];
//! let leaves: Vec<[u8; 32]> = leaf_values
//!         .iter()
//!         .map(|x| Sha256::hash(x.as_bytes()))
//!         .collect();
//!
//! let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
//! let indices_to_prove = vec![3, 4];
//! let leaves_to_prove = leaves.get(3..5).ok_or("can't get leaves to prove")?;
//! let merkle_proof = merkle_tree.proof(&indices_to_prove);
//! let merkle_root = merkle_tree.root().ok_or("couldn't get the merkle root")?;
//! // Serialize proof to pass it to the client
//! let proof_bytes = merkle_proof.to_bytes();
//!
//! // Parse proof back on the client
//! let proof = MerkleProof::<Sha256>::try_from(proof_bytes)?;
//!
//! assert_eq!(proof.verify(merkle_root, &indices_to_prove, leaves_to_prove, leaves.len()), true);
//! # Ok(())
//! # }
//!
//! ```
//!
//! Advanced usage with rolling several commits back:
//!
//! ```
//! # use rs_merkle::{MerkleTree, algorithms::Sha256, Hasher, Error};
//! #
//! #
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let elements = ["a", "b", "c", "d", "e", "f"];
//! let leaves: Vec<[u8; 32]> = elements
//! .iter()
//! .map(|x| Sha256::hash(x.as_bytes()))
//! .collect();
//!
//! let mut merkle_tree: MerkleTree<Sha256> = MerkleTree::new();
//!
//! // Appending leaves to the tree without committing
//! merkle_tree.append(leaves.clone().as_mut());
//!
//! // Without committing changes we can get the root for the uncommitted data, but committed
//! // tree still doesn't have any elements
//! assert_eq!(merkle_tree.root(), None);
//! assert_eq!(merkle_tree.uncommitted_root_hex(), Some("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2".to_string()));
//!
//! // Committing the changes
//! merkle_tree.commit();
//!
//! // Changes applied to the tree after commit, and since there's no new staged changes, committed and
//! // uncommitted tree has the same root
//! assert_eq!(merkle_tree.root_hex(), Some("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2".to_string()));
//! assert_eq!(merkle_tree.uncommitted_root_hex(), Some("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2".to_string()));
//!
//! // Adding a new leaf
//! merkle_tree.insert(Sha256::hash("g".as_bytes()));
//! merkle_tree.commit();
//!
//! // Root was updated after insertion
//! assert_eq!(merkle_tree.root_hex(), Some("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034".to_string()));
//!
//! // Adding some more leaves
//! merkle_tree.append(vec![
//!     Sha256::hash("h".as_bytes()),
//!     Sha256::hash("k".as_bytes()),
//! ].as_mut());
//! merkle_tree.commit();
//! assert_eq!(merkle_tree.root_hex(), Some("09b6890b23e32e607f0e5f670ab224e36af8f6599cbe88b468f4b0f761802dd6".to_string()));
//!
//! // Rolling back to the previous state
//! merkle_tree.rollback();
//! assert_eq!(merkle_tree.root_hex(), Some("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034".to_string()));
//!
//! // We can rollback multiple times as well
//! merkle_tree.rollback();
//! assert_eq!(merkle_tree.root_hex(), Some("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2".to_string()));
//! # Ok(())
//! # }
//! ```

pub use error::Error;
pub use error::ErrorKind;
pub use hasher::Hasher;
pub use merkle_proof::MerkleProof;
pub use merkle_tree::MerkleTree;
pub use partial_tree::PartialTree;

mod error;
mod hasher;
mod merkle_proof;
mod merkle_tree;
mod partial_tree;
#[doc(hidden)]
pub mod utils;

pub mod algorithms;
