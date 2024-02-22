use crate::decode::{decode_fixed_data, decode_variable_data, decode_variable_data_index};
use crate::encode::encode_fixed_data;
use crate::error::{DecodeError, EncodeError};

///TODO: add control messages
/// A type to distinguish "normal" TSP messages from "control" messages
#[repr(u32)]
#[derive(Debug, Clone)]
pub enum Payload<Bytes: AsRef<[u8]>> {
    /// A TSP message which consists only of a message which will be protected using HPKE
    HpkeMessage(Bytes),
}

/// Type representing a TSP Envelope
#[derive(Debug, Clone)]
pub struct Envelope<'a, Vid> {
    pub sender: Vid,
    pub receiver: Vid,
    pub nonconfidential_header: Option<&'a [u8]>,
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
    payload: Payload<impl AsRef<[u8]>>,
    output: &mut impl for<'a> Extend<&'a u8>,
) -> Result<(), EncodeError> {
    let Payload::HpkeMessage(data) = payload;

    checked_encode_variable_data(TSP_PLAINTEXT, data.as_ref(), output)
}

/// Decode a TSP Payload
pub fn decode_payload(mut stream: &[u8]) -> Result<Payload<&[u8]>, DecodeError> {
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

/// A structure representing a siganture + data that needs to be verified
#[derive(Clone, Debug)]
#[must_use]
pub struct VerificationChallenge<'a> {
    pub associated_data: &'a [u8],
    pub signed_data: &'a [u8],
    pub signature: &'a Signature,
}

/// Decode an encrypted TSP message plus Envelope & Signature
pub fn decode_envelope<'a, Vid: TryFrom<&'a [u8]>>(
    mut stream: &'a [u8],
) -> Result<(Envelope<Vid>, VerificationChallenge<'a>, &'a [u8]), DecodeError> {
    let origin = stream;
    let sender = decode_variable_data(TSP_DEVELOPMENT_VID, &mut stream)
        .ok_or(DecodeError::UnexpectedData)?
        .try_into()
        .map_err(|_| DecodeError::VidError)?;
    let receiver = decode_variable_data(TSP_DEVELOPMENT_VID, &mut stream)
        .ok_or(DecodeError::UnexpectedData)?
        .try_into()
        .map_err(|_| DecodeError::VidError)?;
    let nonconfidential_header = decode_variable_data(TSP_PLAINTEXT, &mut stream);
    let associated_data = &origin[..origin.len() - stream.len()];

    let ciphertext =
        decode_variable_data(TSP_CIPHERTEXT, &mut stream).ok_or(DecodeError::UnexpectedData)?;
    let signed_data = &origin[..origin.len() - stream.len()];
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
        },
        VerificationChallenge {
            associated_data,
            signed_data,
            signature,
        },
        ciphertext,
    ))
}

use std::ops::Range;

pub struct CipherView<'a> {
    data: &'a mut [u8],

    sender: Range<usize>,
    receiver: Range<usize>,
    nonconfidential_header: Option<Range<usize>>,

    associated_data: Range<usize>,
    signature: &'a Signature,

    signed_data: Range<usize>,
    ciphertext: Range<usize>,
}

impl<'a> CipherView<'a> {
    pub fn into_opened<Vid: TryFrom<&'a [u8]>>(
        self,
    ) -> Result<(Envelope<'a, Vid>, &'a mut [u8]), Vid::Error> {
        let (header, cipherdata) = self.data.split_at_mut(self.ciphertext.start);

        let ciphertext = &mut cipherdata[..self.ciphertext.len()];

        let envelope = Envelope {
            sender: header[self.sender.clone()].try_into()?,
            receiver: header[self.receiver.clone()].try_into()?,
            nonconfidential_header: self
                .nonconfidential_header
                .as_ref()
                .map(|range| &header[range.clone()]),
        };

        Ok((envelope, ciphertext))
    }

    pub fn as_challenge(&self) -> VerificationChallenge {
        VerificationChallenge {
            //TODO: having this here is maybe not the best idea from a borrow-checker perspective
            associated_data: &self.data[self.associated_data.clone()],
            signed_data: &self.data[self.signed_data.clone()],
            signature: self.signature,
        }
    }
}

/// Decode an encrypted TSP message plus Envelope & Signature
/// Produces the ciphertext as a mutable stream.
pub fn decode_envelope_mut<'a>(stream: &'a mut [u8]) -> Result<CipherView<'a>, DecodeError> {
    let mut pos = 0;
    let sender = decode_variable_data_index(TSP_DEVELOPMENT_VID, &stream[pos..])
        .ok_or(DecodeError::UnexpectedData)?;
    pos = sender.end;

    let mut receiver = decode_variable_data_index(TSP_DEVELOPMENT_VID, &stream[pos..])
        .ok_or(DecodeError::UnexpectedData)?;
    receiver.start += pos;
    receiver.end += pos;
    pos = receiver.end;

    let mut nonconfidential_header = decode_variable_data_index(TSP_PLAINTEXT, &stream[pos..]);
    if let Some(range) = &mut nonconfidential_header {
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
        nonconfidential_header,

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
    pub nonconfidential_header: Option<&'a [u8]>,
    pub message: Payload<Bytes>,
}

/// Convenience interface which illustrates encoding as a single operation
#[cfg(feature = "demo")]
pub fn encode_tsp_message<Vid: AsRef<[u8]>>(
    Message {
        ref sender,
        ref receiver,
        nonconfidential_header,
        message,
    }: Message<Vid, impl AsRef<[u8]>>,
    encrypt: impl FnOnce(&Vid, Vec<u8>) -> Vec<u8>,
    sign: impl FnOnce(&Vid, &[u8]) -> Signature,
) -> Result<Vec<u8>, EncodeError> {
    let mut cesr = encode_envelope_vec(Envelope {
        sender,
        receiver,
        nonconfidential_header,
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
        Envelope {
            sender,
            receiver,
            nonconfidential_header,
        },
        VerificationChallenge {
            signed_data,
            signature,
            ..
        },
        ciphertext,
    ) = decode_envelope(data)?;

    if !verify(signed_data, &sender, signature) {
        return Err(DecodeError::SignatureError);
    }

    let decrypted = decrypt(&receiver, ciphertext);

    // This illustrates a challenge: unless decryption happens in place, either a needless
    // allocation or at the very least moving the contents of the payload around must occur.
    let Payload::HpkeMessage(message) = decode_payload(&decrypted)?;
    let message = Payload::HpkeMessage(message.to_owned());

    Ok(Message {
        sender,
        receiver,
        nonconfidential_header,
        message,
    })
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
        })
        .unwrap();
        let ciphertext = dummy_crypt(&cesr_payload);
        encode_ciphertext(ciphertext, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let (env, ver, ciphertext) = decode_envelope::<&[u8]>(&outer).unwrap();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, &b"Bobbi"[..]);
        assert_eq!(env.nonconfidential_header, None);

        let Payload::HpkeMessage(data) = decode_payload(dummy_crypt(ciphertext)).unwrap();
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
        })
        .unwrap();
        let ciphertext = dummy_crypt(&cesr_payload);
        encode_ciphertext(ciphertext, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let (env, ver, ciphertext) = decode_envelope::<&[u8]>(&outer).unwrap();
        assert_eq!(ver.signed_data, signed_data);
        assert_eq!(ver.signature, &fixed_sig);
        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, &b"Bobbi"[..]);
        assert_eq!(env.nonconfidential_header, Some(&b"treasure"[..]));

        let Payload::HpkeMessage(data) = decode_payload(dummy_crypt(ciphertext)).unwrap();
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
                nonconfidential_header: Some(b"treasure"),
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
            nonconfidential_header: Some(b"treasure"),
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
                nonconfidential_header: None,
                message: Payload::HpkeMessage(payload),
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

        let Payload::HpkeMessage(content) = tsp.message;
        assert_eq!(&content[..], b"Hello TSP!");
    }

    #[test]
    fn mut_envelope_with_nonconfidential_header() {
        fn dummy_crypt(data: &[u8]) -> &[u8] {
            data
        }
        let fixed_sig = [1; 64];

        let cesr_payload = { encode_payload_vec(Payload::HpkeMessage(b"Hello TSP!")).unwrap() };

        let mut outer = encode_envelope_vec(Envelope {
            sender: &b"Alister"[..],
            receiver: &b"Bobbi"[..],
            nonconfidential_header: Some(b"treasure"),
        })
        .unwrap();
        let ciphertext = dummy_crypt(&cesr_payload);
        encode_ciphertext(ciphertext, &mut outer).unwrap();

        let signed_data = outer.clone();
        encode_signature(&fixed_sig, &mut outer);

        let view = decode_envelope_mut(&mut outer).unwrap();
        assert_eq!(view.as_challenge().signed_data, signed_data);
        assert_eq!(view.as_challenge().signature, &fixed_sig);
        let (env, ciphertext) = view.into_opened::<&[u8]>().unwrap();

        assert_eq!(env.sender, &b"Alister"[..]);
        assert_eq!(env.receiver, &b"Bobbi"[..]);
        assert_eq!(env.nonconfidential_header, Some(&b"treasure"[..]));
        let Payload::HpkeMessage(data) = decode_payload(dummy_crypt(ciphertext)).unwrap();
        assert_eq!(data, b"Hello TSP!");
    }
}
