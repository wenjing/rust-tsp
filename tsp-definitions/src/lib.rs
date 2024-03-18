mod error;
use core::fmt;

pub use crate::error::Error;

pub type KeyData = [u8; 32];
pub type PrivateKeyData<'a> = &'a KeyData;
pub type PublicKeyData<'a> = &'a KeyData;
pub type VidData<'a> = &'a [u8];
pub type NonConfidentialData<'a> = &'a [u8];
pub type TSPMessage = Vec<u8>;

#[derive(Debug)]
pub struct ReceivedTspMessage<Bytes: AsRef<[u8]>, V: VerifiedVid> {
    pub sender: V,
    pub nonconfidential_data: Option<Vec<u8>>,
    pub message: Payload<Bytes>,
}

impl<B: AsRef<[u8]>, T: VerifiedVid> ReceivedTspMessage<B, T> {
    pub fn is_relationship_proposal() {
        todo!();
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Payload<Bytes: AsRef<[u8]>> {
    Content(Bytes),
    NestedMessage(Bytes),
    CancelRelationship,
}

impl<Bytes: AsRef<[u8]>> fmt::Display for Payload<Bytes> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Payload::Content(bytes) => {
                write!(f, "Content: {}", String::from_utf8_lossy(bytes.as_ref()))
            }
            Payload::NestedMessage(bytes) => write!(
                f,
                "Nested Message: {}",
                String::from_utf8_lossy(bytes.as_ref())
            ),
            Payload::CancelRelationship => write!(f, "Cancel"),
        }
    }
}

pub trait VerifiedVid {
    /// A identifier of the Vid as bytes (for inclusion in TSP packets)
    fn identifier(&self) -> &str;

    /// The transport layer endpoint in the transport layer associated with this Vid
    fn endpoint(&self) -> &url::Url;

    /// The verification key that can check signatures made by this Vid
    fn verifying_key(&self) -> PublicKeyData;

    /// The encryption key associated with this Vid
    fn encryption_key(&self) -> PublicKeyData;

    /// The parent VID of this inner VID
    fn parent_vid(&self) -> Option<&str>;

    /// The related sender inner VID for this receiver VID
    fn sender_vid(&self) -> Option<&str>;
}

pub trait Receiver: VerifiedVid {
    /// The PRIVATE key used to decrypt data
    fn decryption_key(&self) -> PrivateKeyData;
}

pub trait Sender: Receiver {
    /// The PRIVATE key used to sign data
    fn signing_key(&self) -> PrivateKeyData;
}
