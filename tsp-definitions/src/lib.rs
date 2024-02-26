mod error;

pub use crate::error::Error;

pub type PrivateKeyData<'a> = &'a [u8; 32];
pub type PublicKeyData<'a> = &'a [u8; 32];
pub type VidData<'a> = &'a [u8];
pub type NonConfidentialData<'a> = &'a [u8];
pub type Payload<'a> = &'a [u8];
pub type Ciphertext = Vec<u8>;

pub trait ResolvedVid {
    fn vid(&self) -> VidData;

    fn verifying_key(&self) -> PublicKeyData;

    fn encryption_key(&self) -> PublicKeyData;
}

pub trait Sender: ResolvedVid {
    fn signing_key(&self) -> PrivateKeyData;
}

pub trait Receiver: ResolvedVid {
    fn decryption_key(&self) -> PrivateKeyData;
}
