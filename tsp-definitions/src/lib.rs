use core::fmt;
use futures::Stream;
use std::pin::Pin;
use tokio_util::bytes::BytesMut;

pub type KeyData = [u8; 32];
pub type Digest = [u8; 32];
pub type PrivateKeyData<'a> = &'a KeyData;
pub type PublicKeyData<'a> = &'a KeyData;
pub type VidData<'a> = &'a [u8];
pub type NonConfidentialData<'a> = &'a [u8];
pub type TSPMessage = Vec<u8>;

pub type TSPStream<E> = Pin<Box<dyn Stream<Item = Result<BytesMut, E>> + Send>>;

#[derive(Debug)]
pub enum MessageType {
    Signed,
    SignedAndEncrypted,
}

#[derive(Debug)]
pub enum ReceivedTspMessage<V: VerifiedVid> {
    GenericMessage {
        sender: V,
        nonconfidential_data: Option<Vec<u8>>,
        message: Vec<u8>,
        message_type: MessageType,
    },
    RequestRelationship {
        sender: V,
        thread_id: Digest,
    },
    AcceptRelationship {
        sender: V,
    },
    CancelRelationship {
        sender: V,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload<Bytes: AsRef<[u8]>> {
    Content(Bytes),
    NestedMessage(Bytes),
    RoutedMessage(Vec<String>, Bytes),
    CancelRelationship,
    RequestRelationship,
    AcceptRelationship { thread_id: Digest },
}

impl<Bytes: AsRef<[u8]>> Payload<Bytes> {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Payload::Content(bytes) => bytes.as_ref(),
            Payload::NestedMessage(bytes) => bytes.as_ref(),
            Payload::RoutedMessage(_, bytes) => bytes.as_ref(),
            Payload::CancelRelationship => &[],
            Payload::RequestRelationship => &[],
            Payload::AcceptRelationship { thread_id } => thread_id,
        }
    }
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
            Payload::RoutedMessage(hops, bytes) => {
                write!(
                    f,
                    "Routed Message: {}, route: [",
                    String::from_utf8_lossy(bytes.as_ref())
                )?;
                for vid in hops {
                    write!(f, "{}", vid)?
                }
                write!(f, "]")
            }
            Payload::CancelRelationship => write!(f, "Cancel Relationship"),
            Payload::RequestRelationship => write!(f, "Request Relationship"),
            Payload::AcceptRelationship { thread_id: _ } => write!(f, "Accept Relationship"),
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

    /// The related relation inner VID for this VID
    fn relation_vid(&self) -> Option<&str>;
}

pub trait Receiver: VerifiedVid {
    /// The PRIVATE key used to decrypt data
    fn decryption_key(&self) -> PrivateKeyData;
}

pub trait Sender: Receiver {
    /// The PRIVATE key used to sign data
    fn signing_key(&self) -> PrivateKeyData;
}
