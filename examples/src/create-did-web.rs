use base64ct::Encoding;
use serde_json::json;
use tsp_crypto::dummy::Dummy;
use tsp_definitions::ResolvedVid;

fn create_dummy(name: &str) {
    let domain = "did.tweede.golf";
    let dummy = Dummy::new(&format!("did:web:{domain}:user:{name}"));

    let doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": format!("did:web:{domain}"),
        "verificationMethod": [
            {
                "id": format!("did:web:{domain}#verification-key"),
                "type": "JsonWebKey2020",
                "controller":  format!("did:web:{domain}"),
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "x": base64ct::Base64Url::encode_string(dummy.verifying_key()),
                }
            },
            {
                "id": format!("did:web:{domain}#encryption-key"),
                "type": "JsonWebKey2020",
                "controller": format!("did:web:{domain}"),
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": base64ct::Base64Url::encode_string(dummy.encryption_key()),
                }
            },
        ],
        "authentication": [
            format!("did:web:{domain}#verification-key"),
        ],
        "keyAgreement": [
            format!("did:web:{domain}#encryption-key"), 
          ]
    });

    println!("{}", serde_json::to_string_pretty(&doc).unwrap())
}

fn main() {
    create_dummy("bob");
}
