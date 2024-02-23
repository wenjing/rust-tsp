use ed25519_dalek::Signer;
use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
};
use rand::{rngs::StdRng, SeedableRng};

use crate::Message;

pub type KemType = X25519HkdfSha256;
pub type Aead = ChaCha20Poly1305;
pub type Kdf = HkdfSha256;

type PrivateKey = <KemType as Kem>::PrivateKey;
type PublicKey = <KemType as Kem>::PublicKey;

pub struct Sender {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub signing_key: ed25519_dalek::SigningKey,
}

pub struct Receiver {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

use tsp_cesr::{DecodedEnvelope, Payload};

impl Message<'_> {
    pub fn seal_hpke(&self, sender: &Sender) -> Vec<u8> {
        let mut csprng = StdRng::from_entropy();
        let mut data = self.cesr_header();

        let message_receiver = PublicKey::from_bytes(self.receiver).unwrap();

        let mut cesr_message = Vec::new();
        tsp_cesr::encode_payload(Payload::HpkeMessage(self.secret_message), &mut cesr_message)
            .unwrap();

        let (encapped_key, mut ciphertext) = hpke::single_shot_seal::<Aead, Kdf, KemType, StdRng>(
            &OpModeS::Auth((&sender.private_key, &sender.public_key)),
            &message_receiver,
            &data,
            &cesr_message,
            &[],
            &mut csprng,
        )
        .unwrap();

        ciphertext.extend(encapped_key.to_bytes());
        tsp_cesr::encode_ciphertext(&ciphertext, &mut data).expect("encoding error");

        // append outer signature
        let signature = sender.signing_key.sign(&data).to_bytes();
        tsp_cesr::encode_signature(&signature, &mut data);

        data
    }

    pub fn unseal_hpke<'a>(data: &'a mut [u8], receiver: &Receiver) -> Message<'a> {
        let view = tsp_cesr::decode_envelope_mut(data).expect("envelope");

        let verif = view.as_challenge();

        // verify outer signature
        let signature = ed25519_dalek::Signature::from(verif.signature);
        receiver
            .verifying_key
            .verify_strict(verif.signed_data, &signature)
            .unwrap();

        let DecodedEnvelope {
            raw_header: info,
            envelope,
            ciphertext,
        } = view.into_opened().expect("vid");

        // signature (64 bytes) + enc key (32 bytes) + tag (16 bytes)
        let (ciphertext, footer) = ciphertext.split_at_mut(ciphertext.len() - 32 - 16);
        let (tag, encapped_key) = footer.split_at(footer.len() - 32);

        let message_sender = PublicKey::from_bytes(envelope.sender).unwrap();
        let encapped_key = <KemType as Kem>::EncappedKey::from_bytes(encapped_key).unwrap();

        hpke::single_shot_open_in_place_detached::<Aead, Kdf, KemType>(
            &OpModeR::Auth(&message_sender),
            &receiver.private_key,
            &encapped_key,
            info,
            ciphertext,
            &[],
            &AeadTag::from_bytes(tag).unwrap(),
        )
        .unwrap();

        let Payload::HpkeMessage(secret_message) = tsp_cesr::decode_payload(ciphertext).unwrap();

        Message {
            sender: envelope.sender.try_into().unwrap(),
            receiver: envelope.receiver.try_into().unwrap(),
            header: envelope.nonconfidential_header.unwrap(),
            secret_message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{KemType, Message, Receiver, Sender};
    use hpke::{Kem, Serializable};
    use rand::{rngs::StdRng, SeedableRng};

    fn setup() -> (Sender, Receiver) {
        let mut csprng = StdRng::from_entropy();

        let (sender_private, sender_public) = KemType::gen_keypair(&mut csprng);
        let (receiver_private, receiver_public) = KemType::gen_keypair(&mut csprng);

        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);

        let receiver = Receiver {
            private_key: receiver_private,
            public_key: receiver_public,
            verifying_key: signing_key.verifying_key(),
        };

        let sender = Sender {
            private_key: sender_private,
            public_key: sender_public,
            signing_key,
        };

        (sender, receiver)
    }

    #[test]
    fn seal_unseal_message() {
        let (sender, receiver) = setup();
        let secret_message = b"hello world";
        let header = b"extra header data";

        let message = Message {
            sender: &sender.public_key.to_bytes().into(),
            receiver: &receiver.public_key.to_bytes().into(),
            header,
            secret_message,
        };

        let mut sealed = message.seal_hpke(&sender);
        let received_message = Message::unseal_hpke(&mut sealed, &receiver);

        assert_eq!(message, received_message);
    }
}
