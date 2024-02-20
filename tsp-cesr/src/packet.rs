use crate::decode::{decode_fixed_data, decode_variable_data};
use crate::encode::encode_fixed_data;
use crate::error::{DecodeError, EncodeError};

///TODO: add control messages
/// A type to distinguish "normal" TSP messages from "control" messages
#[repr(u32)]
#[derive(Debug, Clone)]
pub enum Payload<'a> {
    /// A TSP message which consists only of a message which will be protected using HPKE
    HpkeMessage(&'a [u8]),
}

/// Type representing a TSP Envelope
#[derive(Debug, Clone)]
pub struct Envelope<'a, Vid> {
    pub sender: Vid,
    pub receiver: Vid,
    pub nonconfidential_header: Option<&'a [u8]>,
    pub ciphertext: &'a [u8],
}

/// TODO: something more type safe
pub type Signature = [u8; 64];

const TSP_PLAINTEXT: u32 = (b'B' - b'A') as u32;
const TSP_CIPHERTEXT: u32 = (b'C' - b'A') as u32;
const ED25519_SIGNATURE: u32 = (b'B' - b'A') as u32;

const TSP_DEVELOPMENT_VID: u32 = 183236;

/// Safely encode variable data, returning a soft error in case the size limit is exceeded
fn checked_encode_variable_data(
    identifier: u32,
    payload: &[u8],
    stream: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    const DATA_LIMIT: usize = 50000000;

    if payload.len() >= DATA_LIMIT {
        return Err(EncodeError::PayloadTooLarge);
    }

    crate::encode::encode_variable_data(identifier, payload, stream);
    Ok(())
}

/// Encode a TSP Payload into CESR for encryption
/// TODO: add 'hops'
pub fn encode_payload(
    payload: Payload,
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    let Payload::HpkeMessage(data) = payload;

    checked_encode_variable_data(TSP_PLAINTEXT, data, output)
}

/// Decode a TSP Payload
pub fn decode_payload(mut stream: &[u8]) -> Result<Payload, DecodeError> {
    let payload = decode_variable_data(TSP_PLAINTEXT, &mut stream)
        .map(Payload::HpkeMessage)
        .ok_or(DecodeError::UnexpectedData)?;

    if !stream.is_empty() {
        return Err(DecodeError::TrailingGarbage);
    }

    Ok(payload)
}

/// Encode a encrypted TSP message plus Envelope into CESR
/// TODO: replace types of sender/receiver with VID's (once we have that type)
pub fn encode_envelope<'a, Vid: AsRef<[u8]>>(
    envelope: Envelope<'a, Vid>,
    output: &mut impl for<'b> Extend<&'b u8>,
) -> Result<(), EncodeError> {
    checked_encode_variable_data(TSP_DEVELOPMENT_VID, envelope.sender.as_ref(), output)?;
    checked_encode_variable_data(TSP_DEVELOPMENT_VID, envelope.receiver.as_ref(), output)?;
    if let Some(data) = envelope.nonconfidential_header {
        checked_encode_variable_data(TSP_PLAINTEXT, data, output)?;
    }
    checked_encode_variable_data(TSP_CIPHERTEXT, envelope.ciphertext, output)?;

    Ok(())
}

/// Encode a Ed25519 signature into CESR
/// TODO: replace type with a more precise "signature" type
pub fn encode_signature(signature: &Signature, output: &mut impl for<'a> Extend<&'a u8>) {
    encode_fixed_data(ED25519_SIGNATURE, signature, output);
}

/// Decode an encrypted TSP message plus Envelope & Signature
pub fn decode_envelope<'a, Vid: From<&'a [u8]>>(
    mut stream: &'a [u8],
) -> Result<(Envelope<Vid>, &'a Signature), DecodeError> {
    let sender = decode_variable_data(TSP_DEVELOPMENT_VID, &mut stream)
        .ok_or(DecodeError::UnexpectedData)?
        .into();
    let receiver = decode_variable_data(TSP_DEVELOPMENT_VID, &mut stream)
        .ok_or(DecodeError::UnexpectedData)?
        .into();
    let nonconfidential_header = decode_variable_data(TSP_PLAINTEXT, &mut stream);
    let ciphertext =
        decode_variable_data(TSP_CIPHERTEXT, &mut stream).ok_or(DecodeError::UnexpectedData)?;
    let signature =
        decode_fixed_data(ED25519_SIGNATURE, &mut stream).ok_or(DecodeError::UnexpectedData)?;

    if !stream.is_empty() {
        return Err(DecodeError::TrailingGarbage);
    }

    Ok((
        Envelope {
            sender,
            receiver,
            nonconfidential_header,
            ciphertext,
        },
        signature,
    ))
}

/// Allocating variant of [encode_payload]
#[cfg(any(feature = "alloc", test))]
pub fn encode_payload_vec(payload: Payload) -> Result<Vec<u8>, EncodeError> {
    let mut data = vec![];
    encode_payload(payload, &mut data)?;

    Ok(data)
}

/// Allocating variant of [encode_payload]
#[cfg(any(feature = "alloc", test))]
pub fn encode_envelope_vec<Vid: AsRef<[u8]>>(
    envelope: Envelope<Vid>,
) -> Result<Vec<u8>, EncodeError> {
    let mut data = vec![];
    encode_envelope(envelope, &mut data)?;

    Ok(data)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn envelope_without_nonconfidential_header() {
        fn dummy_crypt(data: &[u8]) -> &[u8] {
            data
        }
        let fixed_sig = [1; 64];

        let cesr_payload = { encode_payload_vec(Payload::HpkeMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: &b"Bobbi"[..],
            nonconfidential_header: None,
            ciphertext: dummy_crypt(&cesr_payload),
        })
        .unwrap();
        encode_signature(&fixed_sig, &mut outer);

        let (env, sig) = decode_envelope::<&[u8]>(&outer).unwrap();
        assert_eq!(sig, &fixed_sig);
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, &b"Bobbi"[..]);
        assert_eq!(env.nonconfidential_header, None);

        let Payload::HpkeMessage(data) = decode_payload(dummy_crypt(env.ciphertext)).unwrap();
        assert_eq!(data, b"Hello TSP!");
    }

    #[test]
    fn envelope_with_nonconfidential_header() {
        fn dummy_crypt(data: &[u8]) -> &[u8] {
            data
        }
        let fixed_sig = [1; 64];

        let cesr_payload = { encode_payload_vec(Payload::HpkeMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: &b"Bobbi"[..],
            nonconfidential_header: Some(b"treasure"),
            ciphertext: dummy_crypt(&cesr_payload),
        })
        .unwrap();
        encode_signature(&fixed_sig, &mut outer);

        let (env, sig) = decode_envelope::<&[u8]>(&outer).unwrap();
        assert_eq!(sig, &fixed_sig);
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, &b"Bobbi"[..]);
        assert_eq!(env.nonconfidential_header, Some(&b"treasure"[..]));

        let Payload::HpkeMessage(data) = decode_payload(dummy_crypt(env.ciphertext)).unwrap();
        assert_eq!(data, b"Hello TSP!");
    }

    #[test]
    fn envelope_failure() {
        let fixed_sig = [1; 64];

        let mut outer = vec![];
        encode_signature(&fixed_sig, &mut outer);
        encode_envelope(
            Envelope {
                sender: &b"Alister"[..],
                receiver: &b"Bobbi"[..],
                nonconfidential_header: Some(b"treasure"),
                ciphertext: &[],
            },
            &mut outer,
        )
        .unwrap();

        assert!(decode_envelope::<&[u8]>(&outer).is_err());
    }

    #[test]
    fn trailing_data() {
        let fixed_sig = [1; 64];

        let mut outer = encode_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: &b"Bobbi"[..],
            nonconfidential_header: Some(b"treasure"),
            ciphertext: &[],
        })
        .unwrap();
        encode_signature(&fixed_sig, &mut outer);
        outer.push(b'-');

        assert!(decode_envelope::<&[u8]>(&outer).is_err());
    }
}
