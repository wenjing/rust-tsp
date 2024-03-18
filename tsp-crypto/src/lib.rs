use tsp_definitions::{
    Error, NonConfidentialData, Payload, Receiver, Sender, TSPMessage, VerifiedVid,
};

mod nonconfidential;
mod tsp_hpke;

pub type Aead = hpke::aead::ChaCha20Poly1305;
pub type Kdf = hpke::kdf::HkdfSha256;
pub type Kem = hpke::kem::X25519HkdfSha256;

/// Encrypt, authenticate and sign and CESR encode a TSP message
pub fn seal(
    sender: &dyn Sender,
    receiver: &dyn VerifiedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    payload: Payload<&[u8]>,
) -> Result<TSPMessage, Error> {
    tsp_hpke::seal::<Aead, Kdf, Kem>(sender, receiver, nonconfidential_data, payload)
}

/// Decode a CESR Authentic Confidential Message, verify the signature and decrypt its contents
pub fn open<'a>(
    receiver: &dyn Receiver,
    sender: &dyn VerifiedVid,
    tsp_message: &'a mut [u8],
) -> Result<(Option<NonConfidentialData<'a>>, Payload<&'a [u8]>), Error> {
    tsp_hpke::open::<Aead, Kdf, Kem>(receiver, sender, tsp_message)
}

/// Construct and sign a non-confidential TSP message
pub fn sign(
    sender: &dyn Sender,
    nonconfidential_data: NonConfidentialData,
) -> Result<TSPMessage, Error> {
    nonconfidential::sign(sender, nonconfidential_data)
}

/// Decode a CESR Authentic Non-Confidential Message, verify the signature and return its contents
pub fn verify<'a>(
    sender: &dyn VerifiedVid,
    tsp_message: &'a mut [u8],
) -> Result<NonConfidentialData<'a>, Error> {
    nonconfidential::verify(sender, tsp_message)
}

#[cfg(test)]
mod tests {
    use tsp_definitions::Payload;
    use tsp_vid::PrivateVid;
    use url::Url;

    use crate::{open, seal};

    #[test]
    fn seal_open_message() {
        let bob = PrivateVid::bind("did:test:bob", Url::parse("tcp:://127.0.0.1:1337").unwrap());
        let alice = PrivateVid::bind(
            "did:test:alice",
            Url::parse("tcp:://127.0.0.1:1337").unwrap(),
        );

        let secret_message: &[u8] = b"hello world";
        let nonconfidential_data = b"extra header data";

        let mut message = seal(
            &bob,
            &alice,
            Some(nonconfidential_data),
            Payload::Content(secret_message),
        )
        .unwrap();

        let (received_nonconfidential_data, received_secret_message) =
            open(&alice, &bob, &mut message).unwrap();

        assert_eq!(received_nonconfidential_data.unwrap(), nonconfidential_data);
        assert_eq!(received_secret_message, Payload::Content(secret_message));
    }
}
