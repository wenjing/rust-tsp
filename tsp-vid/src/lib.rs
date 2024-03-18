use ed25519_dalek::{self as Ed};
use hpke::{kem::X25519HkdfSha256 as KemType, Kem, Serializable};
use rand::rngs::OsRng;
use tsp_definitions::{KeyData, VerifiedVid};

pub mod deserialize;
pub mod resolve;

/// A Vid represents a *verified* Identifier
/// (so it doesn't carry any information that allows to verify it)
#[derive(Clone, Debug)]
pub struct Vid {
    id: String,
    transport: url::Url,
    public_sigkey: Ed::VerifyingKey,
    public_enckey: KeyData,
    sender_vid: Option<String>,
    parent_vid: Option<String>,
}

/// A PrivateVid represents the 'owner' of a particular Vid
#[derive(Clone)]
pub struct PrivateVid {
    vid: Vid,
    sigkey: Ed::SigningKey,
    enckey: KeyData,
}

/// A custom implementation of Debug for PrivateVid to avoid key material from leaking during panics.
impl std::fmt::Debug for PrivateVid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("PrivateVid")
            .field("vid", &self.vid)
            .field("sigkey", &"<secret>")
            .field("enckey", &"<secret>")
            .finish()
    }
}

impl tsp_definitions::VerifiedVid for Vid {
    fn identifier(&self) -> &str {
        self.id.as_ref()
    }

    fn endpoint(&self) -> &url::Url {
        &self.transport
    }

    fn verifying_key(&self) -> &KeyData {
        self.public_sigkey.as_bytes()
    }

    fn encryption_key(&self) -> &KeyData {
        &self.public_enckey
    }

    fn parent_vid(&self) -> Option<&str> {
        self.parent_vid.as_deref()
    }

    fn sender_vid(&self) -> Option<&str> {
        self.sender_vid.as_deref()
    }
}

impl tsp_definitions::VerifiedVid for PrivateVid {
    fn identifier(&self) -> &str {
        self.vid.identifier()
    }

    fn endpoint(&self) -> &url::Url {
        self.vid.endpoint()
    }

    fn verifying_key(&self) -> &KeyData {
        self.vid.verifying_key()
    }

    fn encryption_key(&self) -> &KeyData {
        self.vid.encryption_key()
    }

    fn parent_vid(&self) -> Option<&str> {
        self.vid.parent_vid()
    }

    fn sender_vid(&self) -> Option<&str> {
        self.vid.sender_vid()
    }
}

impl tsp_definitions::Sender for PrivateVid {
    fn signing_key(&self) -> &KeyData {
        self.sigkey.as_bytes()
    }
}

impl tsp_definitions::Receiver for PrivateVid {
    fn decryption_key(&self) -> &KeyData {
        &self.enckey
    }
}

impl AsRef<[u8]> for Vid {
    fn as_ref(&self) -> &[u8] {
        self.identifier().as_bytes()
    }
}

impl PrivateVid {
    pub fn bind(id: impl Into<String>, transport: url::Url) -> Self {
        let sigkey = Ed::SigningKey::generate(&mut OsRng);
        let (enckey, public_enckey) = KemType::gen_keypair(&mut OsRng);

        Self {
            vid: Vid {
                id: id.into(),
                transport,
                public_sigkey: sigkey.verifying_key(),
                public_enckey: public_enckey.to_bytes().into(),
                sender_vid: None,
                parent_vid: None,
            },
            sigkey,
            enckey: enckey.to_bytes().into(),
        }
    }

    pub fn add_nested_did_peer(&mut self, transport: url::Url) -> PrivateVid {
        let sigkey = Ed::SigningKey::generate(&mut OsRng);
        let (enckey, public_enckey) = KemType::gen_keypair(&mut OsRng);

        let mut vid = Vid {
            id: Default::default(),
            transport,
            public_sigkey: sigkey.verifying_key(),
            public_enckey: public_enckey.to_bytes().into(),
            sender_vid: None,
            parent_vid: None,
        };

        vid.id = crate::resolve::did::peer::encode_did_peer(&vid);

        Self {
            vid,
            sigkey,
            enckey: enckey.to_bytes().into(),
        }
    }

    pub fn vid(&self) -> &Vid {
        &self.vid
    }

    pub fn into_vid(self) -> Vid {
        self.vid
    }
}
