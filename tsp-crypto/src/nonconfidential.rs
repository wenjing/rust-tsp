use ed25519_dalek::ed25519::signature::Signer;
use tsp_definitions::{Error, NonConfidentialData, Receiver, Sender, TSPMessage, VerifiedVid};

/// Construct and sign a non-confidential TSP message
pub fn sign(
    sender: &dyn Sender,
    receiver: Option<&dyn Receiver>,
    nonconfidential_data: NonConfidentialData,
) -> Result<TSPMessage, Error> {
    let mut data = Vec::with_capacity(64);
    tsp_cesr::encode_envelope(
        tsp_cesr::Envelope {
            sender: sender.identifier(),
            receiver: receiver.map(|r| r.identifier()),
            nonconfidential_data: Some(nonconfidential_data),
        },
        &mut data,
    )?;

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
) -> Result<NonConfidentialData<'a>, Error> {
    unimplemented!();
}
