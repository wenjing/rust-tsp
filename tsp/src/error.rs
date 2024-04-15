#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error: {0}")]
    Encode(#[from] tsp_cesr::error::EncodeError),
    #[error("Error: {0}")]
    Decode(#[from] tsp_cesr::error::DecodeError),
    #[error("Error: {0}")]
    Transport(#[from] tsp_transport::error::Error),
    #[error("Error: {0}")]
    Crypto(#[from] tsp_crypto::error::Error),
    #[error("Error: {0}")]
    Vid(#[from] tsp_vid::error::Error),
    #[error("Error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Error: {0}")]
    InvalidRoute(String),
    #[error("Error: unresolved vid {0}")]
    UnverifiedVid(String),
}
