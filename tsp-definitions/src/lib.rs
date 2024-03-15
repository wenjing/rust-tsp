mod error;

pub use crate::error::Error;

pub type KeyData = [u8; 32];
pub type PrivateKeyData<'a> = &'a KeyData;
pub type PublicKeyData<'a> = &'a KeyData;
pub type VidData<'a> = &'a [u8];
pub type NonConfidentialData<'a> = &'a [u8];
pub type TSPMessage = Vec<u8>;

#[derive(Debug)]
pub struct ReceivedTspMessage<V: VerifiedVid> {
    pub sender: V,
    pub nonconfidential_data: Option<Vec<u8>>,
    pub message: Vec<u8>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Payload<'a> {
    Content(&'a [u8]),
    CancelRelationship,
}

pub trait VerifiedVid {
    /// A identifier of the Vid as bytes (for inclusion in TSP packets)
    fn identifier(&self) -> &[u8];

    /// The transport layer endpoint in the transport layer associated with this Vid
    fn endpoint(&self) -> &url::Url;

    /// The verification key that can check signatures made by this Vid
    fn verifying_key(&self) -> PublicKeyData;

    /// The encryption key associated with this Vid
    fn encryption_key(&self) -> PublicKeyData;
}

pub trait Receiver: VerifiedVid {
    /// The PRIVATE key used to decrypt data
    fn decryption_key(&self) -> PrivateKeyData;
}

pub trait Sender: Receiver {
    /// The PRIVATE key used to sign data
    fn signing_key(&self) -> PrivateKeyData;
}
