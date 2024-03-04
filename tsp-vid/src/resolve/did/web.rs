use base64ct::{Base64Url, Encoding};
use serde::Deserialize;
use tsp_definitions::Error;
use url::Url;

use crate::Vid;

pub(crate) const SCHEME: &str = "web";

const PROTOCOL: &str = "https://";
const DEFAULT_PATH: &str = ".well-known";
const DOCUMENT: &str = "did.json";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub authentication: Vec<String>,
    pub id: String,
    pub key_agreement: Vec<String>,
    pub service: Vec<Service>,
    pub verification_method: Vec<VerificationMethod>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,
    pub service_endpoint: Url,
    #[serde(rename = "type")]
    pub type_field: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub controller: String,
    pub id: String,
    pub public_key_jwk: PublicKeyJwk,
    #[serde(rename = "type")]
    pub type_field: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyJwk {
    pub crv: String,
    pub kty: String,
    #[serde(rename = "use")]
    pub use_field: String,
    pub x: String,
}

pub fn resolve_url(parts: &[&str]) -> Result<Url, Error> {
    Ok(match parts {
        ["did", "web", domain] => format!("{PROTOCOL}{domain}/{DEFAULT_PATH}/{DOCUMENT}"),
        ["did", "web", domain, "user", username] => {
            format!("{PROTOCOL}{domain}/user/{username}/{DOCUMENT}")
        }
        _ => return Err(Error::InvalidVID),
    }
    .parse()?)
}

pub fn resolve_document(did_document: DidDocument, target_id: &str) -> Result<Vid, Error> {
    let transport = match did_document.service.into_iter().next() {
        Some(service) => service.service_endpoint,
        None => return Err(Error::ResolveVID("No transport found in the DID document")),
    };

    if did_document.id != target_id {
        return Err(Error::ResolveVID("Invalid id specified in DID document"));
    }

    let Some(public_sigkey) = did_document
        .authentication
        .into_iter()
        .next()
        .and_then(|id| {
            did_document
                .verification_method
                .iter()
                .find(|item| item.id == id)
        })
        .and_then(|method| {
            if method.public_key_jwk.crv == "Ed25519" && method.public_key_jwk.use_field == "sig" {
                Base64Url::decode_vec(&method.public_key_jwk.x).ok()
            } else {
                None
            }
        })
        .and_then(|key| <[u8; 32]>::try_from(key).ok())
        .and_then(|key| ed25519_dalek::VerifyingKey::from_bytes(&key).ok())
    else {
        return Err(Error::ResolveVID("No valid sign key found in DID document"));
    };

    let Some(public_enckey) = did_document
        .key_agreement
        .into_iter()
        .next()
        .and_then(|id| {
            did_document
                .verification_method
                .iter()
                .find(|item| item.id == id)
        })
        .and_then(|method| {
            if method.public_key_jwk.crv == "X25519" && method.public_key_jwk.use_field == "enc" {
                Base64Url::decode_vec(&method.public_key_jwk.x).ok()
            } else {
                None
            }
        })
        .and_then(|key| <[u8; 32]>::try_from(key).ok())
    else {
        return Err(Error::ResolveVID(
            "No valid encryption key found in DID document",
        ));
    };

    Ok(Vid {
        id: did_document.id,
        transport,
        public_sigkey,
        public_enckey,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use tsp_definitions::{Error, ResolvedVid};
    use url::Url;

    use crate::resolve::did::web::{resolve_document, DidDocument};

    use super::resolve_url;

    fn resolve_did_string(did: &str) -> Result<Url, Error> {
        let parts = did.split(':').collect::<Vec<&str>>();

        resolve_url(&parts)
    }

    #[test]
    fn test_resolve_url() {
        assert_eq!(
            resolve_did_string("did:web:example.com")
                .unwrap()
                .to_string(),
            "https://example.com/.well-known/did.json"
        );

        assert_eq!(
            resolve_did_string("did:web:example.com:user:bob")
                .unwrap()
                .to_string(),
            "https://example.com/user/bob/did.json"
        );

        assert!(resolve_did_string("did:web:example%20.com").is_err());
        assert!(resolve_did_string("did:web:example.com:user:user:user").is_err());
    }

    #[test]
    fn test_resolve_document() {
        let alice_did_doc = fs::read_to_string("../examples/test/alice-did.json").unwrap();
        let alice_did_doc: DidDocument = serde_json::from_str(&alice_did_doc).unwrap();

        let alice = resolve_document(alice_did_doc, "did:web:did.tweede.golf:user:alice");

        assert_eq!(
            alice.unwrap().identifier(),
            "did:web:did.tweede.golf:user:alice".as_bytes()
        );

        let bob_did_doc = fs::read_to_string("../examples/test/bob-did.json").unwrap();
        let bob_did_doc: DidDocument = serde_json::from_str(&bob_did_doc).unwrap();

        let bob = resolve_document(bob_did_doc, "did:web:did.tweede.golf:user:bob");

        assert_eq!(
            bob.unwrap().identifier(),
            "did:web:did.tweede.golf:user:bob".as_bytes()
        );
    }
}
