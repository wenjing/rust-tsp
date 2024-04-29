use crate::definitions::{KeyData, PrivateVid, VerifiedVid};
use deserialize::{serde_key_data, serde_public_sigkey, serde_sigkey};
use ed25519_dalek::{self as Ed};
use hpke::{kem::X25519HkdfSha256 as KemType, Kem, Serializable};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

pub mod deserialize;
pub mod did;
pub mod error;
pub mod resolve;

pub use did::web::{create_did_web, vid_to_did_document};
pub use error::VidError;
pub use resolve::verify_vid;
use url::Url;

/// A Vid represents a *verified* Identifier
/// (so it doesn't carry any information that allows to verify it)
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vid {
    id: String,
    transport: url::Url,
    #[serde(with = "serde_public_sigkey")]
    public_sigkey: Ed::VerifyingKey,
    #[serde(with = "serde_key_data")]
    public_enckey: KeyData,
}

/// A OwnedVid represents the 'owner' of a particular Vid
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnedVid {
    #[serde(flatten)]
    vid: Vid,
    #[serde(with = "serde_sigkey")]
    sigkey: Ed::SigningKey,
    #[serde(with = "serde_key_data")]
    enckey: KeyData,
}

/// A custom implementation of Debug for PrivateVid to avoid key material from leaking during panics.
impl std::fmt::Debug for OwnedVid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("PrivateVid")
            .field("vid", &self.vid)
            .field("sigkey", &"<secret>")
            .field("enckey", &"<secret>")
            .finish()
    }
}

impl VerifiedVid for Vid {
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
}

impl VerifiedVid for OwnedVid {
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
}

impl PrivateVid for OwnedVid {
    fn signing_key(&self) -> &KeyData {
        self.sigkey.as_bytes()
    }
    fn decryption_key(&self) -> &KeyData {
        &self.enckey
    }
}

impl AsRef<[u8]> for Vid {
    fn as_ref(&self) -> &[u8] {
        self.identifier().as_bytes()
    }
}

impl OwnedVid {
    pub fn bind(id: impl Into<String>, transport: url::Url) -> Self {
        let sigkey = Ed::SigningKey::generate(&mut OsRng);
        let (enckey, public_enckey) = KemType::gen_keypair(&mut OsRng);

        Self {
            vid: Vid {
                id: id.into(),
                transport,
                public_sigkey: sigkey.verifying_key(),
                public_enckey: public_enckey.to_bytes().into(),
            },
            sigkey,
            enckey: enckey.to_bytes().into(),
        }
    }

    pub fn new_did_peer(transport: Url) -> OwnedVid {
        let sigkey = Ed::SigningKey::generate(&mut OsRng);
        let (enckey, public_enckey) = KemType::gen_keypair(&mut OsRng);

        let mut vid = Vid {
            id: Default::default(),
            transport,
            public_sigkey: sigkey.verifying_key(),
            public_enckey: public_enckey.to_bytes().into(),
        };

        vid.id = crate::vid::did::peer::encode_did_peer(&vid);

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
