#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Encode(#[from] tsp_cesr::error::EncodeError),
    #[error("{0}")]
    Decode(#[from] tsp_cesr::error::DecodeError),
    #[error("{0}")]
    Cryptographic(#[from] hpke::HpkeError),
    #[error("{0}")]
    Verify(#[from] ed25519_dalek::ed25519::Error),
    #[error("unknown error")]
    Unknown,
}
