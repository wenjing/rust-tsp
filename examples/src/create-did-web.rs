use base64ct::{Base64Url, Encoding};
use serde_json::json;
use std::fs;
use tsp_definitions::{Receiver, Sender, VerifiedVid};
use tsp_vid::PrivateVid;
use url::Url;

fn create_identity(name: &str) {
    let domain = "did.tsp-test.org";
    let did = format!("did:web:{domain}:user:{name}");
    let private_vid = PrivateVid::bind(&did, Url::parse("tcp://127.0.0.1:1337").unwrap());

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
            "serviceEndpoint": "tcp://127.0.0.1:1337"
        }]
    });

    fs::write(
        format!("examples/test/{name}-did.json"),
        serde_json::to_string_pretty(&did_doc).unwrap(),
    )
    .unwrap();
    fs::write(
        format!("examples/test/{name}.json"),
        serde_json::to_string_pretty(&private_doc).unwrap(),
    )
    .unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Please provide a username");
    }

    create_identity(&args[1]);
}
