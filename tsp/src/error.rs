#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Encode(#[from] tsp_cesr::error::EncodeError),
    #[error("{0}")]
    Decode(#[from] tsp_cesr::error::DecodeError),
    #[error("{0}")]
    Transport(#[from] tsp_transport::error::Error),
    #[error("{0}")]
    Crypto(#[from] tsp_crypto::error::Error),
    #[error("{0}")]
    Vid(#[from] tsp_vid::error::Error),
    #[error("{0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("unresolved vid {0}")]
    UnverifiedVid(String),
}
