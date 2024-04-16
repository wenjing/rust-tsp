#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to encode message {0}")]
    Encode(#[from] tsp_cesr::error::EncodeError),
    #[error("failed to decode message {0}")]
    Decode(#[from] tsp_cesr::error::DecodeError),
    #[error("encryption or decryption failed: {0}")]
    Cryptographic(#[from] hpke::HpkeError),
    #[error("could not verify signature: {0}")]
    Verify(#[from] ed25519_dalek::ed25519::Error),
    #[error("unexpected recipient")]
    UnexpectedRecipient,
    #[error("no ciphertext found in encrypted message")]
    MissingCiphertext,
}
