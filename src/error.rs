use std::fmt::{Debug, Formatter, Display};

#[derive(Copy, Clone, Debug)]
pub enum ErrorKind {
    SerializedProofSizeIsIncorrect,
    NotEnoughHelperNodes
}

#[derive(Clone, Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String
}

impl Error {
    pub fn new(kind: ErrorKind, message: String) -> Self {
        Self { kind, message }
    }

    pub fn not_enough_helper_nodes() -> Self {
        Self::new(
            ErrorKind::NotEnoughHelperNodes,
            String::from("Not enough hashes to reconstruct the root")
        )
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str { &self.message }
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}