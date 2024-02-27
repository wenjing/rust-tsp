use ed25519_dalek::Signer;
use hpke::{aead::AeadTag, Deserializable, OpModeR, OpModeS, Serializable};
use rand::{rngs::StdRng, SeedableRng};
use tsp_cesr::DecodedEnvelope;
use tsp_definitions::{
    Ciphertext, Error, NonConfidentialData, Payload, Receiver, ResolvedVid, Sender,
};

pub(crate) fn seal<A, Kdf, Kem>(
    sender: &dyn Sender,
    receiver: &dyn ResolvedVid,
    nonconfidential_data: Option<NonConfidentialData>,
    secret_message: Payload,
) -> Result<Ciphertext, Error>
where
    A: hpke::aead::Aead,
    Kdf: hpke::kdf::Kdf,
    Kem: hpke::kem::Kem,
{
    let mut csprng = StdRng::from_entropy();

    let mut data = Vec::with_capacity(64);
    tsp_cesr::encode_envelope(
        tsp_cesr::Envelope {
            sender: sender.vid(),
            receiver: receiver.vid(),
            nonconfidential_header: nonconfidential_data,
        },
        &mut data,
    )?;

    // prepare CESR encoded ciphertext
    let mut cesr_message = Vec::with_capacity(
        // plaintext size
        secret_message.len()
        // authenticated encryption tag length
        + AeadTag::<A>::size()
        // encapsulated key length
        + Kem::EncappedKey::size()
        // cesr overhead
        + 6,
    );
    tsp_cesr::encode_payload(
        tsp_cesr::Payload::HpkeMessage(secret_message),
        &mut cesr_message,
    )?;

    // HPKE sender mode: "Auth"
    let sender_decryption_key = Kem::PrivateKey::from_bytes(sender.decryption_key())?;
    let sender_encryption_key = Kem::PublicKey::from_bytes(sender.encryption_key())?;
    let mode = OpModeS::Auth((&sender_decryption_key, &sender_encryption_key));

    // recipient public key
    let message_receiver = Kem::PublicKey::from_bytes(receiver.encryption_key())?;

    // perform encryption
    let (encapped_key, tag) = hpke::single_shot_seal_in_place_detached::<A, Kdf, Kem, StdRng>(
        &mode,
        &message_receiver,
        &data,
        &mut cesr_message,
        &[],
        &mut csprng,
    )?;

    // append the authentication tag and encapsulated key to the end of the ciphertext
    cesr_message.extend(tag.to_bytes());
    cesr_message.extend(encapped_key.to_bytes());

    // encode and append the ciphertext to the envelope data
    tsp_cesr::encode_ciphertext(&cesr_message, &mut data).expect("encoding error");

    // create and append outer signature
    let sign_key = ed25519_dalek::SigningKey::from_bytes(sender.signing_key());
    let signature = sign_key.sign(&data).to_bytes();
    tsp_cesr::encode_signature(&signature, &mut data);

    Ok(data)
}

pub(crate) fn open<'a, A, Kdf, Kem>(
    receiver: &dyn Receiver,
    sender: &dyn ResolvedVid,
    message: &'a mut [u8],
) -> Result<(Option<NonConfidentialData<'a>>, Payload<'a>), Error>
where
    A: hpke::aead::Aead,
    Kdf: hpke::kdf::Kdf,
    Kem: hpke::kem::Kem,
{
    let view = tsp_cesr::decode_envelope_mut(message)?;

    // verify outer signature
    let verification_challange = view.as_challenge();
    let signature = ed25519_dalek::Signature::from(verification_challange.signature);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(sender.verifying_key())?;
    verifying_key.verify_strict(verification_challange.signed_data, &signature)?;

    // decode envelope
    let DecodedEnvelope {
        raw_header: info,
        envelope,
        ciphertext,
    } = view
        .into_opened::<&[u8]>()
        .map_err(|_| tsp_cesr::error::DecodeError::VidError)?;

    // split encapsulated key and authenticated encryption tag length
    let (ciphertext, footer) =
        ciphertext.split_at_mut(ciphertext.len() - AeadTag::<A>::size() - Kem::EncappedKey::size());
    let (tag, encapped_key) = footer.split_at(footer.len() - Kem::EncappedKey::size());

    // construct correct key types
    let sender_encryption_key = Kem::PublicKey::from_bytes(sender.encryption_key())?;
    let receiver_decryption_key = Kem::PrivateKey::from_bytes(receiver.decryption_key())?;
    let encapped_key = Kem::EncappedKey::from_bytes(encapped_key)?;
    let tag = AeadTag::from_bytes(tag)?;

    // decrypt the ciphertext
    hpke::single_shot_open_in_place_detached::<A, Kdf, Kem>(
        &OpModeR::Auth(&sender_encryption_key),
        &receiver_decryption_key,
        &encapped_key,
        info,
        ciphertext,
        &[],
        &tag,
    )?;

    let tsp_cesr::Payload::HpkeMessage(secret_message) = tsp_cesr::decode_payload(ciphertext)?;

    Ok((envelope.nonconfidential_header, secret_message))
}