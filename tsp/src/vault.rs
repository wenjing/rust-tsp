use crate::{
    definitions::{PrivateKeyData, PublicKeyData},
    Error, ExportVid, RelationshipStatus,
};
use aries_askar::{
    kms::{KeyAlg, LocalKey},
    StoreKeyMethod,
};
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
pub struct Vault {
    inner: aries_askar::Store,
    url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Metadata {
    id: String,
    transport: String,
    relation_status: RelationshipStatus,
    relation_vid: Option<String>,
    parent_vid: Option<String>,
    tunnel: Option<Box<[String]>>,
}

#[allow(dead_code)]
impl Vault {
    pub async fn new_sqlite(name: &str, password: &[u8]) -> Result<Self, Error> {
        let pass_key = aries_askar::Store::new_raw_key(Some(password))?;
        let url = format!("sqlite://{name}.sqlite");

        let inner =
            aries_askar::Store::provision(&url, StoreKeyMethod::RawKey, pass_key, None, true)
                .await?;

        Ok(Self { inner, url })
    }

    pub async fn open_sqlite(name: &str, password: &[u8]) -> Result<Self, Error> {
        let pass_key = aries_askar::Store::new_raw_key(Some(password))?;
        let url = format!("sqlite://{name}.sqlite");

        let inner =
            aries_askar::Store::open(&url, Some(StoreKeyMethod::RawKey), pass_key, None).await?;

        Ok(Self { inner, url })
    }

    pub async fn persist(
        &self,
        vids: Vec<ExportVid>,
        extra_data: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        let mut conn = self.inner.session(None).await?;

        for export in vids {
            let id = export.id;

            if let Some(private) = export.sigkey {
                let signing_key = LocalKey::from_secret_bytes(KeyAlg::Ed25519, &private.0)?;
                let signing_key_name = format!("{id}#signing-key");
                conn.insert_key(&signing_key_name, &signing_key, None, None, None)
                    .await?;
            }

            if let Some(private) = export.enckey {
                let decryption_key = LocalKey::from_secret_bytes(KeyAlg::X25519, &private.0)?;
                let decryption_key_name = format!("{id}#decryption-key");
                conn.insert_key(&decryption_key_name, &decryption_key, None, None, None)
                    .await?;
            }

            let verification_key =
                LocalKey::from_public_bytes(KeyAlg::Ed25519, &export.public_sigkey.0)?;
            let verification_key_name = format!("{id}#verification-key");
            conn.insert_key(&verification_key_name, &verification_key, None, None, None)
                .await?;

            let encryption_key =
                LocalKey::from_public_bytes(KeyAlg::X25519, &export.public_enckey.0)?;
            let encryption_key_name = format!("{id}#encryption-key");
            conn.insert_key(&encryption_key_name, &encryption_key, None, None, None)
                .await?;

            if let Ok(data) = serde_json::to_string(&Metadata {
                id: id.to_string(),
                transport: export.transport.to_string(),
                relation_status: export.relation_status,
                relation_vid: export.relation_vid,
                parent_vid: export.parent_vid,
                tunnel: export.tunnel,
            }) {
                conn.insert("vid", &id, data.as_bytes(), None, None).await?;
            }
        }

        if let Some(extra_data) = extra_data {
            conn.insert(
                "extra_data",
                "extra_data",
                extra_data.to_string().as_bytes(),
                None,
                None,
            )
            .await?;
        }

        conn.commit().await?;

        Ok(())
    }

    pub async fn load(&self) -> Result<(Vec<ExportVid>, Option<serde_json::Value>), Error> {
        let mut vids = Vec::new();

        let mut conn = self.inner.session(None).await?;
        let results = conn.fetch_all(Some("vid"), None, None, false).await?;

        for item in results.iter() {
            let data: Metadata = serde_json::from_slice(&item.value)
                .map_err(|_| Error::DecodeState("could not decode vid metadata"))?;

            let id = data.id.clone();

            let verification_key_name = format!("{id}#verification-key");
            let Some(verification_key) = conn.fetch_key(&verification_key_name, false).await?
            else {
                continue;
            };

            let encryption_key_name = format!("{id}#encryption-key");
            let Some(encryption_key) = conn.fetch_key(&encryption_key_name, false).await? else {
                continue;
            };

            let verification_bytes = verification_key
                .load_local_key()?
                .to_public_bytes()?
                .to_vec();
            let encryption_bytes = encryption_key.load_local_key()?.to_public_bytes()?.to_vec();

            let mut vid = ExportVid {
                id: data.id,
                transport: data.transport.parse().map_err(|_| {
                    Error::DecodeState("could not parse transport URL from storage")
                })?,
                public_sigkey: PublicKeyData(verification_bytes.try_into().map_err(|_| {
                    Error::DecodeState("could not parse verification key bytes from storage")
                })?),
                public_enckey: PublicKeyData(encryption_bytes.try_into().map_err(|_| {
                    Error::DecodeState("could not parse encryption key bytes from storage")
                })?),
                sigkey: None,
                enckey: None,
                relation_status: data.relation_status,
                relation_vid: data.relation_vid,
                parent_vid: data.parent_vid,
                tunnel: data.tunnel,
            };

            let signing_key_name = format!("{id}#signing-key");
            let signing_key = conn.fetch_key(&signing_key_name, false).await?;

            let decryption_key_name = format!("{id}#decryption-key");
            let decryption_key = conn.fetch_key(&decryption_key_name, false).await?;

            if let (Some(signing_key), Some(decryption_key)) = (signing_key, decryption_key) {
                vid.sigkey = Some(PrivateKeyData(
                    signing_key
                        .load_local_key()?
                        .to_secret_bytes()?
                        .to_vec()
                        .try_into()
                        .map_err(|_| {
                            Error::DecodeState("could not parse signing key bytes from storage")
                        })?,
                ));
                vid.enckey = Some(PrivateKeyData(
                    decryption_key
                        .load_local_key()?
                        .to_secret_bytes()?
                        .to_vec()
                        .try_into()
                        .map_err(|_| {
                            Error::DecodeState("could not parse decryption key bytes from storage")
                        })?,
                ));
            }

            vids.push(vid);
        }

        let extra_data = match conn.fetch("extra_data", "extra_data", false).await? {
            Some(data) => Some(
                serde_json::from_slice(&data.value)
                    .map_err(|_| Error::DecodeState("could not decode extra data from storage"))?,
            ),
            None => None,
        };

        conn.commit().await?;

        Ok((vids, extra_data))
    }

    pub async fn close(self) -> Result<(), Error> {
        self.inner.close().await?;

        Ok(())
    }

    pub async fn destroy(self) -> Result<(), Error> {
        self.inner.close().await?;
        aries_askar::Store::remove(&self.url).await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{OwnedVid, Store, VerifiedVid};

    use super::*;

    #[tokio::test]
    async fn test_vault() {
        let id = {
            let vault = Vault::new_sqlite("test", b"password").await.unwrap();

            let store = Store::new();
            let vid = OwnedVid::new_did_peer("tcp://127.0.0.1:1337".parse().unwrap());
            store.add_private_vid(vid.clone()).unwrap();

            vault.persist(store.export().unwrap(), None).await.unwrap();

            vid.identifier().to_string()
        };

        {
            let vault = Vault::open_sqlite("test", b"password").await.unwrap();
            let (vids, _) = vault.load().await.unwrap();

            let store = Store::new();
            store.import(vids).unwrap();
            assert!(store.has_private_vid(&id).unwrap());

            vault.destroy().await.unwrap();
        }
    }
}
