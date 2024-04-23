use std::sync::PoisonError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error: {0}")]
    Encode(#[from] crate::cesr::error::EncodeError),
    #[error("Error: {0}")]
    Decode(#[from] crate::cesr::error::DecodeError),
    #[error("Error: {0}")]
    Transport(#[from] crate::transport::TransportError),
    #[error("Error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("Error: {0}")]
    Vid(#[from] crate::vid::VidError),
    #[error("Error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Error: {0}")]
    InvalidRoute(String),
    #[error("Error: {0}")]
    Relationship(String),
    #[error("Error: unresolved vid {0}")]
    UnverifiedVid(String),
    #[error("Internal error")]
    Internal,
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Self::Internal
    }
}
