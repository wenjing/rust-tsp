use tsp_definitions::{Error, VerifiedVid};
use url::Url;

use crate::Vid;

pub(crate) const SCHEME: &str = "peer";

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

    format!("did:peer:2.Vz{verification_key}.Ez{encryption_key}")
}

pub(crate) fn resolve_did_peer(parts: &[&str]) -> Result<Vid, Error> {
    let peer_parts = parts[2].split('.').collect::<Vec<&str>>();

    // only numalgo 2 is supported
    if peer_parts[0] != "2" {
        return Err(Error::InvalidVID);
    }

    let mut public_sigkey = None;
    let mut public_enckey = None;

    for part in &peer_parts[1..] {
        match &part[0..1] {
            "Ez" => {
                public_enckey = bs58::decode(&part[2..])
                    .with_alphabet(bs58::Alphabet::BITCOIN)
                    .into_vec()
                    .ok()
                    .and_then(|k| k.try_into().ok())
            }
            "Vz" => {
                public_sigkey = bs58::decode(&part[2..])
                    .with_alphabet(bs58::Alphabet::BITCOIN)
                    .into_vec()
                    .ok()
                    .and_then(|k| k[2..].try_into().ok())
                    .and_then(|k| ed25519_dalek::VerifyingKey::from_bytes(&k).ok());
            }
            _ => {
                return Err(Error::InvalidVID);
            }
        }
    }

    dbg!(public_sigkey, public_enckey);

    match (public_sigkey, public_enckey) {
        (Some(public_sigkey), Some(public_enckey)) => Ok(Vid {
            id: Default::default(),
            transport: Url::parse("tcp://127.0.0.1:1337").unwrap(),
            public_sigkey,
            public_enckey,
            sender_vid: None,
            parent_vid: None,
        }),
        _ => Err(Error::InvalidVID),
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

    #[ignore]
    #[test]
    fn encode_decode() {
        let sigkey = Ed::SigningKey::generate(&mut OsRng);
        let (_enckey, public_enckey) = KemType::gen_keypair(&mut OsRng);

        let mut vid = Vid {
            id: Default::default(),
            transport: Url::parse("tcp://127.0.0.1:1337").unwrap(),
            public_sigkey: sigkey.verifying_key(),
            public_enckey: public_enckey.to_bytes().into(),
            sender_vid: None,
            parent_vid: None,
        };

        vid.id = encode_did_peer(&vid);

        let parts = vid.id.split(':').collect::<Vec<&str>>();

        let resolved_vid = resolve_did_peer(&parts).unwrap();

        assert_eq!(vid.verifying_key(), resolved_vid.verifying_key());
        assert_eq!(vid.encryption_key(), resolved_vid.encryption_key());
    }
}
