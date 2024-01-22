use std::io::Write;

use faster_hex::hex_string_upper;
use hpke::{
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use vid::{Identifier, SelfSignedVid};
type KemType = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;

type PrivateKey = <KemType as Kem>::PrivateKey;
type PublicKey = <KemType as Kem>::PublicKey;

type Data = Vec<u8>;
type EncappedKey = [u8; 32];

#[derive(Serialize, Deserialize, PartialEq, Clone)]
struct SignedEnvelope {
    pub(crate) sender: SelfSignedVid,
    pub(crate) receiver: SelfSignedVid,
}

impl std::fmt::Debug for SignedEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedEnvelope")
            .field("sender", &self.sender.display())
            .field("receiver", &self.receiver.display())
            .finish()
    }
}

impl SignedEnvelope {
    pub fn sender_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.sender.public_key().as_ref()).unwrap()
    }

    pub fn receiver_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.sender.public_key().as_ref()).unwrap()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let sender = self.sender.display();
        let receiver = self.receiver.display();
        let mut result = Vec::<u8>::with_capacity(sender.len() + receiver.len());

        result
            .write_all(&(sender.len() as u16).to_be_bytes())
            .unwrap();
        result
            .write_all(&(receiver.len() as u16).to_be_bytes())
            .unwrap();
        result.write_all(sender.as_bytes()).unwrap();
        result.write_all(receiver.as_bytes()).unwrap();

        result
    }

    pub fn deserialize(data: &[u8]) -> (SignedEnvelope, usize) {
        let sender_len = ((data[0] as u16) << 8) | data[1] as u16;
        let receiver_len = ((data[2] as u16) << 8) | data[3] as u16;

        let sender_offset = sender_len as usize + 4;
        let receiver_offset = sender_offset + receiver_len as usize;

        let result = SignedEnvelope {
            sender: SelfSignedVid::parse(std::str::from_utf8(&data[4..sender_offset]).unwrap())
                .unwrap(),
            receiver: SelfSignedVid::parse(
                std::str::from_utf8(&data[sender_offset..receiver_offset]).unwrap(),
            )
            .unwrap(),
        };

        (result, receiver_offset)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Message {
    signed_envelope: SignedEnvelope,
    #[serde(with = "faster_hex")]
    secret_message: Data,
}

#[derive(Serialize, Deserialize)]
struct SealedMessage {
    version_major: u8,
    version_minor: u8,
    signed_envelope: Data,
    encapped_key: EncappedKey,
    ciphertext: Data,
}

impl SealedMessage {
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::with_capacity(
            1 // major
            + 1 // minor
            + self.signed_envelope.len()
            + 32 // encapped key length
            + 16 // signature length
            + self.ciphertext.len(),
        );

        result.insert(0, self.version_major);
        result.insert(1, self.version_minor);
        result.write_all(&self.signed_envelope).unwrap();
        result.write_all(&self.encapped_key).unwrap();
        result.write_all(&self.ciphertext).unwrap();

        result
    }

    pub fn deserialize(data: &[u8]) -> (SignedEnvelope, SealedMessage) {
        let version_major = data[0];
        let version_minor = data[1];

        let (signed_envelope_decoded, offset) = SignedEnvelope::deserialize(&data[2..]);
        let signed_envelope = data[2..(offset + 2)].to_owned();
        let encapped_key: EncappedKey = data[(offset + 2)..(offset + 34)].try_into().unwrap();
        let ciphertext: Data = data[(offset + 34)..].to_owned();

        let sealed_message = SealedMessage {
            version_major,
            version_minor,
            signed_envelope,
            encapped_key,
            ciphertext,
        };

        (signed_envelope_decoded, sealed_message)
    }
}

impl std::fmt::Debug for SealedMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedMessage")
            .field("version_major", &self.version_major)
            .field("version_minor", &self.version_minor)
            .field("signed_envelope", &hex_string_upper(&self.signed_envelope))
            .field("ciphertext", &hex_string_upper(&self.ciphertext))
            .field("encapped_key", &hex_string_upper(&self.encapped_key))
            .finish()
    }
}

impl Message {
    const MAJOR_VERSION: u8 = 0;
    const MINOR_VERSION: u8 = 1;

    pub fn seal(self, key: PrivateKey) -> Vec<u8> {
        let mut csprng = StdRng::from_entropy();

        let (encapped_key, mut sender_ctx) = hpke::setup_sender::<Aead, Kdf, KemType, _>(
            &OpModeS::Auth((key, self.signed_envelope.sender_key())),
            &self.signed_envelope.receiver_key(),
            self.signed_envelope.sender.display().as_bytes(),
            &mut csprng,
        )
        .expect("invalid server pubkey!");

        let signed_envelope = self.signed_envelope.serialize();
        let ciphertext = sender_ctx
            .seal(&self.secret_message, &signed_envelope)
            .expect("encryption failed!");

        let sealed_message = SealedMessage {
            version_major: Self::MAJOR_VERSION,
            version_minor: Self::MINOR_VERSION,
            signed_envelope,
            ciphertext,
            encapped_key: encapped_key.to_bytes().into(),
        };

        sealed_message.serialize()
    }

    pub fn unseal(data: &[u8], key: PrivateKey) -> Message {
        let (signed_envelope, sealed_message) = SealedMessage::deserialize(data);

        let encapped_key = <KemType as Kem>::EncappedKey::from_bytes(&sealed_message.encapped_key)
            .expect("could not deserialize the encapsulated pubkey!");

        let mut receiver_ctx = hpke::setup_receiver::<Aead, Kdf, KemType>(
            &OpModeR::Auth(signed_envelope.sender_key()),
            &key,
            &encapped_key,
            signed_envelope.sender.display().as_bytes(),
        )
        .expect("failed to set up receiver!");

        let secret_message = receiver_ctx
            .open(&sealed_message.ciphertext, &sealed_message.signed_envelope)
            .expect("invalid ciphertext!");

        Message {
            signed_envelope,
            secret_message,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{KemType, Message, PrivateKey, SignedEnvelope};
    use hpke::{Kem, Serializable};
    use rand::{rngs::StdRng, SeedableRng};
    use vid::{SecretKey, SelfSignedVid, SigningKey};

    fn setup() -> (PrivateKey, PrivateKey, SignedEnvelope) {
        let mut csprng = StdRng::from_entropy();

        let (sender_private, sender_pub) = KemType::gen_keypair(&mut csprng);
        let (receiver_private, receiver_pub) = KemType::gen_keypair(&mut csprng);

        let sender_secret = SecretKey::from(sender_private.to_bytes());
        let receiver_secret = SecretKey::from(receiver_private.to_bytes());

        let sender_key = SigningKey::from_bytes(&sender_secret);
        let receiver_key = SigningKey::from_bytes(&receiver_secret);

        let sender = SelfSignedVid::generate_from_key(
            "mailto:bob@example.com".parse().unwrap(),
            &sender_key,
        );
        let receiver = SelfSignedVid::generate_from_key(
            "mailto:alice@example.com".parse().unwrap(),
            &receiver_key,
        );

        let envelope = SignedEnvelope { sender, receiver };

        // vid roundtrip test
        assert_eq!(envelope.sender_key(), sender_pub);
        assert_eq!(envelope.receiver_key(), receiver_pub);

        (
            sender_private,
            receiver_private,
            envelope
        )
    }

    #[test]
    fn encode_signed_envelope() {
        let (_, _, signed_envelope) = setup();

        let result = signed_envelope.serialize();
        assert!(result
            .windows(3)
            .position(|window| window == b"bob")
            .is_some());

        let (original, _) = SignedEnvelope::deserialize(&result);

        assert_eq!(original.sender, signed_envelope.sender);
        assert_eq!(original.receiver, signed_envelope.receiver);
    }

    #[test]
    fn seal_unseal_message() {
        let (sender_private, receiver_private, signed_envelope) = setup();
        let secret_message = b"hello world".to_vec();

        let message = Message {
            signed_envelope,
            secret_message,
        };

        let sealed = message.clone().seal(sender_private);
        let received_message = Message::unseal(&sealed, receiver_private);

        assert_eq!(sealed.len(), 137);
        assert_eq!(message, received_message);
    }
}
