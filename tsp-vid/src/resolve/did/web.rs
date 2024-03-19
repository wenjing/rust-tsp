use base64ct::{Base64Url, Encoding};
use serde::Deserialize;
use serde_json::json;
use tsp_definitions::{Error, Receiver, Sender, VerifiedVid};
use url::Url;

use crate::{PrivateVid, Vid};

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
    pub service_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub controller: String,
    pub id: String,
    pub public_key_jwk: PublicKeyJwk,
    #[serde(rename = "type")]
    pub method_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyJwk {
    pub crv: String,
    pub kty: String,
    #[serde(rename = "use")]
    pub usage: String,
    pub x: String,
}

pub fn resolve_url(parts: &[&str]) -> Result<Url, Error> {
    Ok(match parts {
        ["did", "web", domain] => format!("{PROTOCOL}{domain}/{DEFAULT_PATH}/{DOCUMENT}"),
        ["did", "web", domain, "user", username] => {
            format!("{PROTOCOL}{domain}/user/{username}/{DOCUMENT}")
        }
        _ => return Err(Error::InvalidVID("unknown VID type")),
    }
    .parse()?)
}

pub fn find_first_key(
    did_document: &DidDocument,
    method: &[String],
    curve: &str,
    usage: &str,
) -> Option<[u8; 32]> {
    method
        .iter()
        .next()
        .and_then(|id| {
            did_document
                .verification_method
                .iter()
                .find(|item| &item.id == id)
        })
        .and_then(|method| {
            if method.public_key_jwk.crv == curve && method.public_key_jwk.usage == usage {
                Base64Url::decode_vec(&method.public_key_jwk.x).ok()
            } else {
                None
            }
        })
        .and_then(|key| <[u8; 32]>::try_from(key).ok())
}

pub fn resolve_document(did_document: DidDocument, target_id: &str) -> Result<Vid, Error> {
    if did_document.id != target_id {
        return Err(Error::ResolveVID("Invalid id specified in DID document"));
    }

    let Some(public_sigkey) = find_first_key(
        &did_document,
        &did_document.authentication,
        "Ed25519",
        "sig",
    )
    .and_then(|key| ed25519_dalek::VerifyingKey::from_bytes(&key).ok()) else {
        return Err(Error::ResolveVID("No valid sign key found in DID document"));
    };

    let Some(public_enckey) =
        find_first_key(&did_document, &did_document.key_agreement, "X25519", "enc")
    else {
        return Err(Error::ResolveVID(
            "No valid encryption key found in DID document",
        ));
    };

    let transport = match did_document.service.into_iter().next().and_then(|service| {
        if service.service_type == "TSPTransport" {
            Some(service)
        } else {
            None
        }
    }) {
        Some(service) => service.service_endpoint,
        None => return Err(Error::ResolveVID("No transport found in the DID document")),
    };

    Ok(Vid {
        id: did_document.id,
        transport,
        public_sigkey,
        public_enckey,
        relation_vid: None,
        parent_vid: None,
    })
}

pub fn create_did_web(
    name: &str,
    domain: &str,
    transport: &str,
) -> (serde_json::Value, serde_json::Value) {
    let did = format!("did:web:{domain}:user:{name}");
    let private_vid = PrivateVid::bind(&did, Url::parse(transport).unwrap());

    let private_doc = json!({
        "vid": did,
        "decryption-key": Base64Url::encode_string(private_vid.decryption_key()),
        "signing-key": Base64Url::encode_string(private_vid.signing_key()),
    });

    let did_doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{did}#verification-key"),
                "type": "JsonWebKey2020",
                "controller":  format!("{did}"),
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "x": Base64Url::encode_string(private_vid.verifying_key()),
                }
            },
            {
                "id": format!("{did}#encryption-key"),
                "type": "JsonWebKey2020",
                "controller": format!("{did}"),
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": Base64Url::encode_string(private_vid.encryption_key()),
                }
            },
        ],
        "authentication": [
            format!("{did}#verification-key"),
        ],
        "keyAgreement": [
            format!("{did}#encryption-key"),
        ],
        "service": [{
            "id": "#tsp-transport",
            "type": "TSPTransport",
            "serviceEndpoint": transport
        }]
    });

    (did_doc, private_doc)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use tsp_definitions::{Error, VerifiedVid};
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

        let alice = resolve_document(alice_did_doc, "did:web:did.tsp-test.org:user:alice");

        assert_eq!(
            alice.unwrap().identifier(),
            "did:web:did.tsp-test.org:user:alice"
        );

        let bob_did_doc = fs::read_to_string("../examples/test/bob-did.json").unwrap();
        let bob_did_doc: DidDocument = serde_json::from_str(&bob_did_doc).unwrap();

        let bob = resolve_document(bob_did_doc, "did:web:did.tsp-test.org:user:bob");

        assert_eq!(
            bob.unwrap().identifier(),
            "did:web:did.tsp-test.org:user:bob"
        );
    }
}
