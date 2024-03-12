/// Constants that determine the specific CESR types for "variable length data"
const TSP_PLAINTEXT: u32 = (b'B' - b'A') as u32;
const TSP_CIPHERTEXT: u32 = (b'C' - b'A') as u32;
const TSP_DEVELOPMENT_VID: u32 = (21 << 6 | 8) << 6 | 3; // "VID"

/// Constants that determine the specific CESR types for "fixed length data"
const TSP_TYPECODE: u32 = (b'X' - b'A') as u32;
const ED25519_SIGNATURE: u32 = (b'B' - b'A') as u32;
#[allow(clippy::eq_op)]
const TSP_NONCE: u32 = (b'A' - b'A') as u32;
const TSP_SHA256: u32 = (b'I' - b'A') as u32;
const ED25519_PUBLICKEY: u32 = (b'D' - b'A') as u32;
const HPKE_PUBLICKEY: u32 = (b'Q' - b'A') as u32;

/// Constants that determine the specific CESR types for the framing codes
const TSP_WRAPPER: u16 = (b'E' - b'A') as u16;
const TSP_PAYLOAD: u16 = (b'Z' - b'A') as u16;

/// Constants to encode message types
mod msgtype {
    pub(super) const GEN_MSG: [u8; 2] = [0, 0];
    pub(super) const NEW_REL: [u8; 2] = [1, 0];
    pub(super) const NEW_REL_REPLY: [u8; 2] = [1, 1];
    pub(super) const NEW_NEST_REL: [u8; 2] = [1, 2];
    pub(super) const NEW_NEST_REL_REPLY: [u8; 2] = [1, 3];
}

use crate::{
    decode::{decode_count, decode_fixed_data, decode_variable_data, decode_variable_data_index},
    encode::{encode_count, encode_fixed_data},
    error::{DecodeError, EncodeError},
};

/// A type to enforce that a random nonce contains enough bits of security
/// (128bits via a birthday attack -> 256bits needed)
pub type Nonce = [u8; 32];

/// A *public* key pair
//TODO: this probably belongs in tsp-definitions; but that's not possible right now
//due to a circular dependency; this can be solved by removing the workspaces
#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PairedKeys<'a> {
    pub signing: &'a [u8; 32],
    pub encrypting: &'a [u8; 32],
}

///TODO: add control messages
/// A type to distinguish "normal" TSP messages from "control" messages
#[repr(u32)]
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum Payload<'a, Bytes: AsRef<[u8]>> {
    /// A TSP message which consists only of a message which will be protected using HPKE
    GenericMessage(Bytes),
    /// A TSP message requesting a relationship
    DirectRelationProposal { nonce: &'a Nonce },
    /// A TSP message confiming a relationship
    DirectRelationAffirm { reply: &'a [u8] },
    /// A TSP message requesting a nested relationship
    NestedRelationProposal { public_keys: PairedKeys<'a> },
    /// A TSP message confiming a relationship
    NestedRelationAffirm {
        reply: &'a [u8],
        public_keys: PairedKeys<'a>,
    },
}

/// Type representing a TSP Envelope
#[derive(Debug, Clone)]
pub struct Envelope<'a, Vid> {
    pub sender: Vid,
    pub receiver: Vid,
    pub nonconfidential_data: Option<&'a [u8]>,
}

pub struct DecodedEnvelope<'a, Vid, Bytes> {
    pub envelope: Envelope<'a, Vid>,
    pub raw_header: &'a [u8], // for associated data purposes
    pub ciphertext: Bytes,
}

/// TODO: something more type safe
pub type Signature = [u8; 64];

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
    payload: Payload<impl AsRef<[u8]>>,
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    encode_count(TSP_PAYLOAD, 1, output);
    match payload {
        Payload::GenericMessage(data) => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::GEN_MSG, output);
            checked_encode_variable_data(TSP_PLAINTEXT, data.as_ref(), output)?;
        }
        Payload::DirectRelationProposal { nonce } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::NEW_REL, output);
            encode_fixed_data(TSP_NONCE, nonce, output);
        }
        Payload::DirectRelationAffirm { reply } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::NEW_REL_REPLY, output);
            encode_fixed_data(TSP_SHA256, reply, output);
        }
        Payload::NestedRelationProposal { public_keys } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::NEW_NEST_REL, output);
            encode_fixed_data(ED25519_PUBLICKEY, public_keys.signing, output);
            encode_fixed_data(HPKE_PUBLICKEY, public_keys.encrypting, output);
        }
        Payload::NestedRelationAffirm { reply, public_keys } => {
            encode_fixed_data(TSP_TYPECODE, &msgtype::NEW_NEST_REL_REPLY, output);
            encode_fixed_data(TSP_SHA256, reply, output);
            encode_fixed_data(ED25519_PUBLICKEY, public_keys.signing, output);
            encode_fixed_data(HPKE_PUBLICKEY, public_keys.encrypting, output);
        }
    }

    Ok(())
}

/// Decode a TSP Payload
pub fn decode_payload(mut stream: &[u8]) -> Result<Payload<&[u8]>, DecodeError> {
    let Some(1) = decode_count(TSP_PAYLOAD, &mut stream) else {
        return Err(DecodeError::VersionMismatch);
    };

    let payload =
        match decode_fixed_data(TSP_TYPECODE, &mut stream).ok_or(DecodeError::UnexpectedData)? {
            &msgtype::GEN_MSG => {
                decode_variable_data(TSP_PLAINTEXT, &mut stream).map(Payload::GenericMessage)
            }
            _ => {
                todo!()
            }
        };

    if !stream.is_empty() {
        Err(DecodeError::TrailingGarbage)
    } else {
        payload.ok_or(DecodeError::UnexpectedData)
    }
}

/// Encode a encrypted TSP message plus Envelope into CESR
/// TODO: replace types of sender/receiver with VID's (once we have that type)
pub fn encode_envelope<'a, Vid: AsRef<[u8]>>(
    envelope: Envelope<'a, Vid>,
    output: &mut impl for<'b> Extend<&'b u8>,
) -> Result<(), EncodeError> {
    encode_count(TSP_WRAPPER, 1, output);
    encode_fixed_data(TSP_TYPECODE, &[0, 0], output);
    checked_encode_variable_data(TSP_DEVELOPMENT_VID, envelope.sender.as_ref(), output)?;
    checked_encode_variable_data(TSP_DEVELOPMENT_VID, envelope.receiver.as_ref(), output)?;
    if let Some(data) = envelope.nonconfidential_data {
        checked_encode_variable_data(TSP_PLAINTEXT, data, output)?;
    }

    Ok(())
}

/// Encode a Ed25519 signature into CESR
/// TODO: replace type with a more precise "signature" type
pub fn encode_signature(signature: &Signature, output: &mut impl for<'a> Extend<&'a u8>) {
    encode_fixed_data(ED25519_SIGNATURE, signature, output);
}

/// Encode a encrypted ciphertext into CESR
pub fn encode_ciphertext(
    ciphertext: &[u8],
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    checked_encode_variable_data(TSP_CIPHERTEXT, ciphertext, output)
}

/// Checks whether the expected TSP header is present and returns its size
fn detected_tsp_header_size(stream: &mut &[u8]) -> Result<usize, DecodeError> {
    let origin = stream as &[u8];
    match decode_count(TSP_WRAPPER, stream) {
        Some(1) => {}
        _ => return Err(DecodeError::VersionMismatch),
    }
    match decode_fixed_data(TSP_TYPECODE, stream) {
        Some([0, 0]) => {}
        _ => return Err(DecodeError::VersionMismatch),
    }

    debug_assert_eq!(origin.len() - stream.len(), 6);
    Ok(6)
}

/// A structure representing a siganture + data that needs to be verified
#[derive(Clone, Debug)]
#[must_use]
pub struct VerificationChallenge<'a> {
    pub signed_data: &'a [u8],
    pub signature: &'a Signature,
}

/// Decode an encrypted TSP message plus Envelope & Signature
pub fn decode_envelope<'a, Vid: TryFrom<&'a [u8]>>(
    mut stream: &'a [u8],
) -> Result<
    (
        DecodedEnvelope<'a, Vid, &'a [u8]>,
        VerificationChallenge<'a>,
    ),
    DecodeError,
> {
    let origin = stream;
    detected_tsp_header_size(&mut stream)?;
    let sender = decode_variable_data(TSP_DEVELOPMENT_VID, &mut stream)
        .ok_or(DecodeError::UnexpectedData)?
        .try_into()
        .map_err(|_| DecodeError::VidError)?;
    let receiver = decode_variable_data(TSP_DEVELOPMENT_VID, &mut stream)
        .ok_or(DecodeError::UnexpectedData)?
        .try_into()
        .map_err(|_| DecodeError::VidError)?;
    let nonconfidential_data = decode_variable_data(TSP_PLAINTEXT, &mut stream);
    let raw_header = &origin[..origin.len() - stream.len()];

    let ciphertext =
        decode_variable_data(TSP_CIPHERTEXT, &mut stream).ok_or(DecodeError::UnexpectedData)?;
    let signed_data = &origin[..origin.len() - stream.len()];
    let signature =
        decode_fixed_data(ED25519_SIGNATURE, &mut stream).ok_or(DecodeError::UnexpectedData)?;

    if !stream.is_empty() {
        return Err(DecodeError::TrailingGarbage);
    }

    Ok((
        DecodedEnvelope {
            envelope: Envelope {
                sender,
                receiver,
                nonconfidential_data,
            },
            raw_header,
            ciphertext,
        },
        VerificationChallenge {
            signed_data,
            signature,
        },
    ))
}

use std::ops::Range;

pub struct CipherView<'a> {
    data: &'a mut [u8],

    sender: Range<usize>,
    receiver: Range<usize>,
    nonconfidential_data: Option<Range<usize>>,

    associated_data: Range<usize>,
    signature: &'a Signature,

    signed_data: Range<usize>,
    ciphertext: Range<usize>,
}

impl<'a> CipherView<'a> {
    pub fn into_opened<Vid: TryFrom<&'a [u8]>>(
        self,
    ) -> Result<DecodedEnvelope<'a, Vid, &'a mut [u8]>, Vid::Error> {
        let (header, cipherdata) = self.data.split_at_mut(self.ciphertext.start);

        let ciphertext = &mut cipherdata[..self.ciphertext.len()];

        let raw_header = &header[self.associated_data.clone()];

        let envelope = Envelope {
            sender: header[self.sender.clone()].try_into()?,
            receiver: header[self.receiver.clone()].try_into()?,
            nonconfidential_data: self
                .nonconfidential_data
                .as_ref()
                .map(|range| &header[range.clone()]),
        };

        Ok(DecodedEnvelope {
            envelope,
            raw_header,
            ciphertext,
        })
    }

    pub fn as_challenge(&self) -> VerificationChallenge {
        VerificationChallenge {
            signed_data: &self.data[self.signed_data.clone()],
            signature: self.signature,
        }
    }
}

/// Decode an encrypted TSP message plus Envelope & Signature
/// Produces the ciphertext as a mutable stream.
pub fn decode_envelope_mut<'a>(stream: &'a mut [u8]) -> Result<CipherView<'a>, DecodeError> {
    let mut pos = detected_tsp_header_size(&mut (stream as &[u8]))?;
    let mut sender = decode_variable_data_index(TSP_DEVELOPMENT_VID, &stream[pos..])
        .ok_or(DecodeError::UnexpectedData)?;
    sender.start += pos;
    sender.end += pos;
    pos = sender.end;

    let mut receiver = decode_variable_data_index(TSP_DEVELOPMENT_VID, &stream[pos..])
        .ok_or(DecodeError::UnexpectedData)?;
    receiver.start += pos;
    receiver.end += pos;
    pos = receiver.end;

    let mut nonconfidential_data = decode_variable_data_index(TSP_PLAINTEXT, &stream[pos..]);
    if let Some(range) = &mut nonconfidential_data {
        range.start += pos;
        range.end += pos;
        pos = range.end;
    }

    let associated_data = 0..pos;

    let mut ciphertext = decode_variable_data_index(TSP_CIPHERTEXT, &stream[pos..])
        .ok_or(DecodeError::UnexpectedData)?;
    ciphertext.start += pos;
    ciphertext.end += pos;
    pos = ciphertext.end;

    let signed_data = 0..pos;

    let data: &'a mut [u8];
    let mut sigdata: &[u8];
    (data, sigdata) = stream.split_at_mut(signed_data.end);

    let signature =
        decode_fixed_data(ED25519_SIGNATURE, &mut sigdata).ok_or(DecodeError::UnexpectedData)?;

    if !sigdata.is_empty() {
        return Err(DecodeError::TrailingGarbage);
    }

    Ok(CipherView {
        data,

        sender,
        receiver,
        nonconfidential_data,

        associated_data,
        signature,

        signed_data,
        ciphertext,
    })
}

/// Allocating variant of [encode_payload]
#[cfg(any(feature = "alloc", test))]
pub fn encode_payload_vec(payload: Payload<impl AsRef<[u8]>>) -> Result<Vec<u8>, EncodeError> {
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

/// Convenience interface: this struct is isomorphic to [Envelope] but represents
/// a "opened" envelope, i.e. message.
#[cfg(feature = "demo")]
#[derive(Debug, Clone)]
pub struct Message<'a, Vid, Bytes: AsRef<[u8]>> {
    pub sender: Vid,
    pub receiver: Vid,
    pub nonconfidential_data: Option<&'a [u8]>,
    pub message: Payload<Bytes>,
}

/// Convenience interface which illustrates encoding as a single operation
#[cfg(feature = "demo")]
pub fn encode_tsp_message<Vid: AsRef<[u8]>>(
    Message {
        ref sender,
        ref receiver,
        nonconfidential_data,
        message,
    }: Message<Vid, impl AsRef<[u8]>>,
    encrypt: impl FnOnce(&Vid, Vec<u8>) -> Vec<u8>,
    sign: impl FnOnce(&Vid, &[u8]) -> Signature,
) -> Result<Vec<u8>, EncodeError> {
    let mut cesr = encode_envelope_vec(Envelope {
        sender,
        receiver,
        nonconfidential_data,
    })?;

    let ciphertext = &encrypt(receiver, encode_payload_vec(message)?);

    encode_ciphertext(ciphertext, &mut cesr)?;
    encode_signature(&sign(sender, &cesr), &mut cesr);

    Ok(cesr)
}

/// A convenience interface which illustrates decoding as a single operation
#[cfg(feature = "demo")]
pub fn decode_tsp_message<'a, Vid: TryFrom<&'a [u8]>>(
    data: &'a [u8],
    decrypt: impl FnOnce(&Vid, &[u8]) -> Vec<u8>,
    verify: impl FnOnce(&[u8], &Vid, &Signature) -> bool,
) -> Result<Message<Vid, Vec<u8>>, DecodeError> {
    let (
        DecodedEnvelope {
            envelope:
                Envelope {
                    sender,
                    receiver,
                    nonconfidential_data,
                },
            ciphertext,
            ..
        },
        VerificationChallenge {
            signed_data,
            signature,
        },
    ) = decode_envelope(data)?;

    if !verify(signed_data, &sender, signature) {
        return Err(DecodeError::SignatureError);
    }

    let decrypted = decrypt(&receiver, ciphertext);

    // This illustrates a challenge: unless decryption happens in place, either a needless
    // allocation or at the very least moving the contents of the payload around must occur.
    let Payload::GenericMessage(message) = decode_payload(&decrypted)?;
    let message = Payload::GenericMessage(message.to_owned());

    Ok(Message {
        sender,
        receiver,
        nonconfidential_data,
        message,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn envelope_without_nonconfidential_data() {
        fn dummy_crypt(data: &[u8]) -> &[u8] {
            data
        }
        let fixed_sig = [1; 64];

        let cesr_payload = { encode_payload_vec(Payload::GenericMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: &b"Bobbi"[..],
            nonconfidential_data: None,
        })
        .unwrap();
        let ciphertext = dummy_crypt(&cesr_payload);
        encode_ciphertext(ciphertext, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let (
            DecodedEnvelope {
                envelope: env,
                ciphertext,
                ..
            },
            ver,
        ) = decode_envelope::<&[u8]>(&outer).unwrap();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, &b"Bobbi"[..]);
        assert_eq!(env.nonconfidential_data, None);

        let Payload::GenericMessage(data) = decode_payload(dummy_crypt(ciphertext)).unwrap() else {
            unreachable!();
        };
        assert_eq!(data, b"Hello TSP!");
    }

    #[test]
    fn envelope_with_nonconfidential_data() {
        fn dummy_crypt(data: &[u8]) -> &[u8] {
            data
        }
        let fixed_sig = [1; 64];

        let cesr_payload = { encode_payload_vec(Payload::GenericMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: &b"Bobbi"[..],
            nonconfidential_data: Some(b"treasure"),
        })
        .unwrap();
        let ciphertext = dummy_crypt(&cesr_payload);
        encode_ciphertext(ciphertext, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let (
            DecodedEnvelope {
                envelope: env,
                ciphertext,
                ..
            },
            ver,
        ) = decode_envelope::<&[u8]>(&outer).unwrap();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, &b"Bobbi"[..]);
        assert_eq!(env.nonconfidential_data, Some(&b"treasure"[..]));

        let Payload::GenericMessage(data) = decode_payload(dummy_crypt(ciphertext)).unwrap() else {
            unreachable!();
        };
        assert_eq!(data, b"Hello TSP!");
    }

    #[test]
    fn envelope_failure() {
        let fixed_sig = [1; 64];

        let mut outer = vec![];
        encode_envelope(
            Envelope {
                sender: &b"Alister"[..],
                receiver: &b"Bobbi"[..],
                nonconfidential_data: Some(b"treasure"),
            },
            &mut outer,
        )
        .unwrap();
        encode_signature(&fixed_sig, &mut outer);
        encode_ciphertext(&[], &mut outer).unwrap();

        assert!(decode_envelope::<&[u8]>(&outer).is_err());
    }

    #[test]
    fn trailing_data() {
        let fixed_sig = [1; 64];

        let mut outer = encode_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: &b"Bobbi"[..],
            nonconfidential_data: Some(b"treasure"),
        })
        .unwrap();
        encode_ciphertext(&[], &mut outer).unwrap();
        encode_signature(&fixed_sig, &mut outer);
        outer.push(b'-');

        assert!(decode_envelope::<&[u8]>(&outer).is_err());
    }

    #[cfg(feature = "demo")]
    #[test]
    fn convenience() {
        let sender = b"Alister".as_slice();
        let receiver = b"Bobbi".as_slice();
        let payload = b"Hello TSP!";
        let data = encode_tsp_message(
            Message {
                sender,
                receiver,
                nonconfidential_data: None,
                message: Payload::GenericMessage(payload),
            },
            |_, vec| vec,
            |_, _| [5; 64],
        )
        .unwrap();

        let tsp = decode_tsp_message(
            &data,
            |_: &&[u8], x| x.to_vec(),
            |_, _, sig| sig == &[5u8; 64],
        )
        .unwrap();

        assert_eq!(tsp.sender, b"Alister".as_slice());
        assert_eq!(tsp.receiver, b"Bobbi");

        let Payload::GenericMessage(content) = tsp.message;
        assert_eq!(&content[..], b"Hello TSP!");
    }

    #[test]
    fn mut_envelope_with_nonconfidential_data() {
        test_turn_around(Payload::GenericMessage(&b"Hello TSP!"[..]));
    }

    fn test_turn_around(payload: Payload<&[u8]>) {
        fn dummy_crypt(data: &[u8]) -> &[u8] {
            data
        }
        let fixed_sig = [1; 64];

        let cesr_payload = encode_payload_vec(payload.clone()).unwrap();

        let mut outer = encode_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: &b"Bobbi"[..],
            nonconfidential_data: Some(b"treasure"),
        })
        .unwrap();
        let ciphertext = dummy_crypt(&cesr_payload);
        encode_ciphertext(ciphertext, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let view = decode_envelope_mut(&mut outer).unwrap();
        assert_eq!(view.as_challenge().signed_data, signed_data);
        assert_eq!(view.as_challenge().signature, &fixed_sig);
        let DecodedEnvelope {
            envelope: env,
            ciphertext,
            ..
        } = view.into_opened::<&[u8]>().unwrap();

        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, &b"Bobbi"[..]);
        assert_eq!(env.nonconfidential_data, Some(&b"treasure"[..]));

        assert_eq!(decode_payload(dummy_crypt(ciphertext)).unwrap(), payload);
    }

    #[test]
    fn test_relation_forming() {
        let temp = (1u8..33).collect::<Vec<u8>>();
        let nonce: &[u8; 32] = temp.as_slice().try_into().unwrap();
        test_turn_around(Payload::DirectRelationProposal { nonce });
        test_turn_around(Payload::DirectRelationAffirm { reply: nonce });
    }
}
