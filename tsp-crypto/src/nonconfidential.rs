use ed25519_dalek::ed25519::signature::Signer;
use tsp_definitions::{Error, Payload, Sender, TSPMessage, VerifiedVid};

/// Construct and sign a non-confidential TSP message
pub fn sign(
    sender: &dyn Sender,
    receiver: Option<&dyn VerifiedVid>,
    payload: Payload<&[u8]>,
) -> Result<TSPMessage, Error> {
    let mut data = Vec::with_capacity(64);
    tsp_cesr::encode_s_envelope(
        tsp_cesr::Envelope {
            sender: sender.identifier(),
            receiver: receiver.map(|r| r.identifier()),
            nonconfidential_data: None,
        },
        &mut data,
    )?;

    let payload = match payload {
        Payload::Content(data) => tsp_cesr::Payload::GenericMessage(data),
        Payload::Cancel => tsp_cesr::Payload::RelationshipCancel,
        Payload::NestedMessage(_) => todo!(),
    };

    tsp_cesr::encode_payload(payload, &mut data)?;

    // create and append signature
    let sign_key = ed25519_dalek::SigningKey::from_bytes(sender.signing_key());
    let signature = sign_key.sign(&data).to_bytes();
    tsp_cesr::encode_signature(&signature, &mut data);

    Ok(data)
}

/// Decode a CESR Authentic Non-Confidential Message, verify the signature and return its contents
pub fn verify<'a>(
    _sender: &dyn VerifiedVid,
    _tsp_message: &'a mut [u8],
) -> Result<Payload<&'a [u8]>, Error> {
    unimplemented!();
}
