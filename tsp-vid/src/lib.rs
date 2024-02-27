use ed25519_dalek::{self as Ed};
use hpke::{kem::X25519HkdfSha256 as KemType, Kem, Serializable};
use rand::rngs::OsRng;
use tsp_definitions::{KeyData, ResolvedVid};

pub mod resolve;

/// A Vid represents a *verified* Identifier
/// (so it doesn't carry any information that allows to verify it)
#[derive(Clone, Debug)]
pub struct Vid<Identifier> {
    id: Identifier,
    transport: url::Url,
    public_sigkey: Ed::VerifyingKey,
    public_enckey: KeyData,
}

/// A VidController represents the 'owner' of a particular Vid
#[derive(Clone)]
pub struct VidController<Identifier> {
    vid: Vid<Identifier>,
    sigkey: Ed::SigningKey,
    enckey: KeyData,
}

/// A custom implementation of Debug for VidController to avoid key material from leaking during panics.
impl<I: std::fmt::Debug> std::fmt::Debug for VidController<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("VidController")
            .field("vid", &self.vid)
            .field("sigkey", &"<secret>")
            .field("enckey", &"<secret>")
            .finish()
    }
}

impl<Identifier: AsRef<[u8]>> tsp_definitions::ResolvedVid for Vid<Identifier> {
    fn identifier(&self) -> &[u8] {
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

impl<Identifier: AsRef<[u8]>> tsp_definitions::ResolvedVid for VidController<Identifier> {
    fn identifier(&self) -> &[u8] {
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

impl<Identifier: AsRef<[u8]>> tsp_definitions::Sender for VidController<Identifier> {
    fn signing_key(&self) -> &KeyData {
        self.sigkey.as_bytes()
    }
}

impl<Identifier: AsRef<[u8]>> tsp_definitions::Receiver for VidController<Identifier> {
    fn decryption_key(&self) -> &KeyData {
        &self.enckey
    }
}

impl<Identifier: AsRef<[u8]>> AsRef<[u8]> for Vid<Identifier> {
    fn as_ref(&self) -> &[u8] {
        self.identifier()
    }
}

impl<Identifier> VidController<Identifier> {
    pub fn bind(id: Identifier, transport: url::Url) -> Self {
        let sigkey = Ed::SigningKey::generate(&mut OsRng);
        let (enckey, public_enckey) = KemType::gen_keypair(&mut OsRng);

        Self {
            vid: Vid {
                id,
                transport,
                public_sigkey: sigkey.verifying_key(),
                public_enckey: public_enckey.to_bytes().into(),
            },
            sigkey,
            enckey: enckey.to_bytes().into(),
        }
    }

    pub fn vid(&self) -> &Vid<Identifier> {
        &self.vid
    }

    pub fn into_vid(self) -> Vid<Identifier> {
        self.vid
    }
}
