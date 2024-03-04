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
    #[error("{0}")]
    Request(#[from] reqwest::Error),
    #[error("{0}")]
    ParseUrl(#[from] url::ParseError),
    #[error("{0}")]
    ParseJson(#[from] serde_json::Error),
    #[error("{0}")]
    Base64(#[from] base64ct::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("could not deserialize key {0}")]
    ParseKey(#[from] std::array::TryFromSliceError),
    #[error("could not resolve VID {0}")]
    ResolveVID(&'static str),
    #[error("unexpected recipient")]
    UnexpectedRecipient,
    #[error("unknown VID type")]
    UnknownVIDType,
    #[error("invalid VID")]
    InvalidVID,
    #[error("invalid address")]
    InvalidAddress,
    #[error("invalid transport scheme")]
    InvalidTransportScheme,
    #[error("unknown error")]
    Unknown,
}
