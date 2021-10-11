use std::fmt::{Debug, Display, Formatter};

#[derive(Copy, Clone, Debug)]
pub enum ErrorKind {
    SerializedProofSizeIsIncorrect,
    NotEnoughHelperNodes,
    HashConversionError,
    NotEnoughHashesToCalculateRoot,
}

#[derive(Clone, Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: String) -> Self {
        Self { kind, message }
    }

    pub fn not_enough_helper_nodes() -> Self {
        Self::new(
            ErrorKind::NotEnoughHelperNodes,
            String::from("not enough hashes to reconstruct the root"),
        )
    }

    pub fn wrong_proof_size(proof_len: usize, hash_size: usize) -> Self {
        Self::new(
            ErrorKind::SerializedProofSizeIsIncorrect,
            format!(
                "proof of size {} bytes can not be divided into chunks of {} bytes",
                proof_len, hash_size,
            ),
        )
    }

    pub fn vec_to_hash_conversion_error() -> Self {
        Self::new(
            ErrorKind::HashConversionError,
            "couldn't convert proof hash data into Hasher::Hash".to_string(),
        )
    }

    pub fn not_enough_hashes_to_calculate_root() -> Self {
        Self::new(
            ErrorKind::NotEnoughHashesToCalculateRoot,
            "proof doesn't contain enough data to extract the root".to_string(),
        )
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
