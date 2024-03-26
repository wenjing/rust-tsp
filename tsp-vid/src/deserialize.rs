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

        let sigkey = base64ct::Base64UrlUnpadded::decode_vec(&vid_data.signing_key)?;
        let enckey = base64ct::Base64UrlUnpadded::decode_vec(&vid_data.decryption_key)?;

        Ok(Self {
            vid: resolved,
            sigkey: Ed::SigningKey::from_bytes(sigkey.as_slice().try_into()?),
            enckey: enckey.as_slice().try_into()?,
        })
    }
}

pub(crate) mod serde_key_data {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};
    use tsp_definitions::KeyData;

    pub fn serialize<S>(key: &KeyData, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let key = Base64UrlUnpadded::encode_string(key);
        serializer.serialize_str(&key)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<KeyData, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: &str = Deserialize::deserialize(deserializer)?;
        let key = Base64UrlUnpadded::decode_vec(encoded).map_err(serde::de::Error::custom)?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| serde::de::Error::custom("key data is not exactly 32 bytes"))?;

        Ok(key)
    }
}

pub(crate) mod serde_sigkey {
    use super::Ed;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &Ed::SigningKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let key = Base64UrlUnpadded::encode_string(key.as_bytes());
        serializer.serialize_str(&key)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ed::SigningKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: &str = Deserialize::deserialize(deserializer)?;
        let key = Base64UrlUnpadded::decode_vec(encoded).map_err(serde::de::Error::custom)?;
        let key: &[u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(serde::de::Error::custom)?;

        Ok(Ed::SigningKey::from_bytes(key))
    }
}

pub(crate) mod serde_public_sigkey {
    use super::Ed;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &Ed::VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let key = Base64UrlUnpadded::encode_string(key.as_bytes());
        serializer.serialize_str(&key)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ed::VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: &str = Deserialize::deserialize(deserializer)?;
        let key = Base64UrlUnpadded::decode_vec(encoded).map_err(serde::de::Error::custom)?;
        let key: &[u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(serde::de::Error::custom)?;

        Ed::VerifyingKey::from_bytes(key).map_err(serde::de::Error::custom)
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
