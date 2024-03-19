use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::json;
use tsp_definitions::{Error, VerifiedVid};
use url::Url;

use crate::Vid;

pub(crate) const SCHEME: &str = "peer";

/// Encode VID as did:peer,include verification end encryption key
/// The service definition has type `tsp`
/// See https://identity.foundation/peer-did-method-spec/
pub(crate) fn encode_did_peer(vid: &Vid) -> String {
    let mut v = Vec::with_capacity(34);
    // multicodec for ed25519-pub
    v.push(0xed);
    // 32 bytes length
    v.push(0x20);
    v.extend_from_slice(vid.verifying_key());

    let verification_key = bs58::encode(&v)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string();

    v.clear();
    // multicodec for x25519-pub
    v.push(0xec);
    // 32 bytes length
    v.push(0x20);
    v.extend_from_slice(vid.encryption_key());

    let encryption_key = bs58::encode(&v)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string();

    let service = Base64UrlUnpadded::encode_string(
        json!({
            "t": "tsp",
            "s": {
                "uri": vid.endpoint()
            }
        })
        .to_string()
        .as_bytes(),
    );

    format!("did:peer:2.Vz{verification_key}.Ez{encryption_key}.S{service}")
}

pub(crate) fn resolve_did_peer(parts: &[&str]) -> Result<Vid, Error> {
    let peer_parts = parts[2].split('.').collect::<Vec<&str>>();

    // only numalgo 2 is supported
    if peer_parts[0] != "2" {
        return Err(Error::InvalidVID(
            "only numalgo 2 is supported for did:peer",
        ));
    }

    let mut public_sigkey = None;
    let mut public_enckey = None;
    let mut transport = None;

    for part in &peer_parts[1..] {
        match &part[0..2] {
            // Key Agreement (Encryption) + base58 multibase prefix
            "Ez" => {
                let enckey_bytes = bs58::decode(&part[2..])
                    .with_alphabet(bs58::Alphabet::BITCOIN)
                    .into_vec()?;

                // multicodec for x25519-pub + length 32 bytes
                if enckey_bytes[0] != 0xec || enckey_bytes[1] != 0x20 {
                    return Err(Error::InvalidVID("invalid encryption key type in did:peer"));
                }

                public_enckey = enckey_bytes[2..].try_into().ok();
            }
            // Authentication (Verification) + base58 multibase prefix
            "Vz" => {
                let sigkey_bytes = bs58::decode(&part[2..])
                    .with_alphabet(bs58::Alphabet::BITCOIN)
                    .into_vec()?;

                // multicodec for ed25519-pub + length 32 bytes
                if sigkey_bytes[0] != 0xed || sigkey_bytes[1] != 0x20 {
                    return Err(Error::InvalidVID(
                        "invalid verification key type in did:peer",
                    ));
                }

                if let Ok(sigkey_bytes) = sigkey_bytes[2..].try_into() {
                    public_sigkey = ed25519_dalek::VerifyingKey::from_bytes(sigkey_bytes).ok();
                }
            }
            // start of base64url encoded service definition
            "Se" => {
                let transport_bytes = Base64UrlUnpadded::decode_vec(&part[1..])?;
                let transport_json: serde_json::Value = serde_json::from_slice(&transport_bytes)?;

                if transport_json["t"] != "tsp" {
                    return Err(Error::InvalidVID("invalid transport type in did:peer"));
                }

                if let Some(transport_bytes) = &transport_json["s"]["uri"].as_str() {
                    transport = Url::parse(transport_bytes).ok();
                }
            }
            _ => {
                return Err(Error::InvalidVID("invalid part in did:peer"));
            }
        }
    }

    match (public_sigkey, public_enckey, transport) {
        (Some(public_sigkey), Some(public_enckey), Some(transport)) => Ok(Vid {
            id: parts.join(":"),
            transport,
            public_sigkey,
            public_enckey,
            relation_vid: None,
            parent_vid: None,
        }),
        (None, _, _) => Err(Error::InvalidVID("missing verification key in did:peer")),
        (_, None, _) => Err(Error::InvalidVID("missing encryption key in did:peer")),
        (_, _, None) => Err(Error::InvalidVID("missing transport in did:peer")),
    }
}

#[cfg(test)]
mod test {
    use ed25519_dalek::{self as Ed};
    use hpke::{kem::X25519HkdfSha256 as KemType, Kem, Serializable};
    use rand::rngs::OsRng;
    use tsp_definitions::VerifiedVid;
    use url::Url;

    use crate::Vid;

    use super::{encode_did_peer, resolve_did_peer};

    #[test]
    fn encode_decode() {
        let sigkey = Ed::SigningKey::generate(&mut OsRng);
        let (_enckey, public_enckey) = KemType::gen_keypair(&mut OsRng);

        let mut vid = Vid {
            id: Default::default(),
            transport: Url::parse("tcp://127.0.0.1:1337").unwrap(),
            public_sigkey: sigkey.verifying_key(),
            public_enckey: public_enckey.to_bytes().into(),
            relation_vid: None,
            parent_vid: None,
        };

        vid.id = encode_did_peer(&vid);

        let parts = vid.id.split(':').collect::<Vec<&str>>();

        let resolved_vid = resolve_did_peer(&parts).unwrap();

        assert_eq!(vid.verifying_key(), resolved_vid.verifying_key());
        assert_eq!(vid.encryption_key(), resolved_vid.encryption_key());
        assert_eq!(vid.endpoint(), resolved_vid.endpoint());
    }
}
