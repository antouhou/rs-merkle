use crate::{hasher::Hash, prelude::*, Error, MerkleProof, MerkleProofSerializer};

/// Serializes proof data to bytes with a reverse hash order - hashes are concatenated from
/// top to bottom, right to left.
pub struct ReverseHashesOrder {}

impl MerkleProofSerializer for ReverseHashesOrder {
    fn serialize<H: Hash>(proof: &MerkleProof<H>) -> Vec<u8> {
        let mut hashes: Vec<Vec<u8>> = proof
            .proof_hashes()
            .iter()
            .cloned()
            .map(|hash| hash.into())
            .collect();

        hashes.reverse();
        hashes.drain(..).flatten().collect()
    }

    fn deserialize<H: Hash>(bytes: &[u8]) -> Result<MerkleProof<H>, Error> {
        if bytes.len() % H::SIZE != 0 {
            return Err(Error::wrong_proof_size(bytes.len(), H::SIZE));
        }

        let hashes_count = bytes.len() / H::SIZE;
        let mut proof_hashes_slices = Vec::<H>::with_capacity(hashes_count);

        for i in 0..hashes_count {
            let slice_start = i * H::SIZE;
            let slice_end = (i + 1) * H::SIZE;
            let slice = bytes
                .get(slice_start..slice_end)
                .ok_or_else(Error::vec_to_hash_conversion_error)?;
            let vec = Vec::from(slice);
            match H::try_from(vec) {
                Ok(val) => proof_hashes_slices.push(val),
                Err(_) => return Err(Error::vec_to_hash_conversion_error()),
            }
        }

        proof_hashes_slices.reverse();

        Ok(MerkleProof::new(proof_hashes_slices))
    }
}
