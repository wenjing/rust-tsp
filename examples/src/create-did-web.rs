use std::fs;

use base64ct::{Base64Url, Encoding};
use serde_json::json;
use tsp_crypto::dummy::Dummy;
use tsp_definitions::{Receiver, ResolvedVid, Sender};

fn create_dummy(name: &str) {
    let domain = "did.tweede.golf";
    let did = format!("did:web:{domain}:user:{name}");
    let dummy = Dummy::new(&did);

    let private_doc = json!({
        "vid": did,
        "decryption-key": Base64Url::encode_string(dummy.decryption_key()),
        "signing-key": Base64Url::encode_string(dummy.signing_key()),
    });

    let did_doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": format!("did:web:{domain}"),
        "verificationMethod": [
            {
                "id": format!("{did}#verification-key"),
                "type": "JsonWebKey2020",
                "controller":  format!("{did}"),
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "x": Base64Url::encode_string(dummy.verifying_key()),
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
                    "x": Base64Url::encode_string(dummy.encryption_key()),
                }
            },
        ],
        "authentication": [
            format!("{did}#verification-key"),
        ],
        "keyAgreement": [
            format!("{did}#encryption-key"),
          ]
    });

    fs::write(
        format!("examples/test/{name}-did.json"),
        serde_json::to_string_pretty(&did_doc).unwrap(),
    )
    .unwrap();
    fs::write(
        format!("examples/test/{name}.identity"),
        serde_json::to_string_pretty(&private_doc).unwrap(),
    )
    .unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Please provide a username");
    }

    create_dummy(&args[1]);
}
