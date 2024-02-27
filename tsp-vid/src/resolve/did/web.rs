use base64ct::{Base64Url, Encoding};
use serde::Deserialize;
use tsp_definitions::Error;
use url::Url;

use crate::Vid;

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

pub fn resolve_url(parts: &[&str]) -> Result<String, Error> {
    match parts {
        ["did", "web", domain] => Ok(format!("{PROTOCOL}{domain}/{DEFAULT_PATH}/{DOCUMENT}")),
        ["did", "web", domain, "user", username] => {
            Ok(format!("{PROTOCOL}{domain}/user/{username}/{DOCUMENT}"))
        }
        _ => Err(Error::InvalidVID),
    }
}

pub fn resolve_document<Identifier: ToString>(
    did_document: DidDocument,
    id: Identifier,
) -> Result<Vid<Identifier>, Error> {
    let transport = match did_document.service.into_iter().next() {
        Some(service) => service.service_endpoint,
        None => return Err(Error::ResolveVID("No transport found in the DID document")),
    };

    if did_document.id != id.to_string() {
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
        id,
        transport,
        public_sigkey,
        public_enckey,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn resolve_did_url() {}
}
