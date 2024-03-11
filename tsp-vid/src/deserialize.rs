use base64ct::Encoding;
use ed25519_dalek::{self as Ed};
use serde::Deserialize;
use std::path::Path;
use tokio::fs;
use tsp_definitions::Error;

use crate::{resolve::resolve_vid, PrivateVid};

#[derive(Deserialize)]
struct SecretVidData {
    #[serde(rename = "decryption-key")]
    decryption_key: String,
    #[serde(rename = "signing-key")]
    signing_key: String,
    vid: String,
}

impl PrivateVid {
    pub async fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let vid_data = fs::read_to_string(path).await?;
        let vid_data: SecretVidData = serde_json::from_str(&vid_data)?;

        let resolved = resolve_vid(&vid_data.vid).await?;

        let sigkey = base64ct::Base64Url::decode_vec(&vid_data.signing_key)?;
        let enckey = base64ct::Base64Url::decode_vec(&vid_data.decryption_key)?;

        Ok(Self {
            vid: resolved,
            sigkey: Ed::SigningKey::from_bytes(sigkey.as_slice().try_into()?),
            enckey: enckey.as_slice().try_into()?,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::PrivateVid;

    #[tokio::test]
    async fn deserialize() {
        let alice = PrivateVid::from_file("../examples/test/alice.json")
            .await
            .unwrap();

        assert_eq!(alice.vid().id, "did:web:did.tsp-test.org:user:alice");
        assert_eq!(alice.vid().transport.as_str(), "tcp://127.0.0.1:1337");
    }
}
