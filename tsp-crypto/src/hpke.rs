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

#[derive(Clone)]
pub struct Keypair {
    pub name: String,
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub signing_key: ed25519_dalek::SigningKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

impl Message<'_> {
    pub fn seal_hpke(&self, sender: &Keypair) -> Vec<u8> {
        let mut csprng = StdRng::from_entropy();
        let mut data = self.serialize_header();

        let mut ciphertext = self.secret_message.to_vec();
        let message_receiver = PublicKey::from_bytes(self.receiver).unwrap();

        let (encapped_key, tag) =
            hpke::single_shot_seal_in_place_detached::<Aead, Kdf, KemType, StdRng>(
                &OpModeS::Auth((&sender.private_key, &sender.public_key)),
                &message_receiver,
                &data,
                &mut ciphertext,
                &[],
                &mut csprng,
            )
            .unwrap();

        let mut encapped_key = encapped_key.to_bytes().to_vec();
        let mut tag = tag.to_bytes().to_vec();

        data.append(&mut ciphertext);
        data.append(&mut tag);
        data.append(&mut encapped_key);

        // append outer signature
        data.extend_from_slice(&sender.signing_key.sign(&data).to_bytes());

        data
    }

    pub fn unseal_hpke<'a>(
        data: &'a mut [u8],
        receiver: &Keypair,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Message<'a> {
        let header_len = u16::from_be_bytes(data[..2].try_into().unwrap()) as usize;
        let signature_split = data.len() - 64;

        // verify outer signature
        let signature = ed25519_dalek::Signature::try_from(&data[signature_split..]).unwrap();
        verifying_key
            .verify_strict(&data[..signature_split], &signature)
            .unwrap();

        // decode message
        let (encoded_header, rest) = data.split_at_mut(header_len + 66);
        let message_sender_bytes = &encoded_header[2..34];
        let mesage_receiver_bytes = &encoded_header[34..66];

        // signature (64 bytes) + enc key (32 bytes) + tag (16 bytes)
        let (ciphertext, footer) = rest.split_at_mut(rest.len() - (64 + 32 + 16));
        let header = &encoded_header[66..];
        let tag = &footer[0..16];
        let encapped_key = &footer[16..(16 + 32)];

        let message_sender = PublicKey::from_bytes(message_sender_bytes).unwrap();
        let encapped_key = <KemType as Kem>::EncappedKey::from_bytes(encapped_key).unwrap();

        hpke::single_shot_open_in_place_detached::<Aead, Kdf, KemType>(
            &OpModeR::Auth(&message_sender),
            &receiver.private_key,
            &encapped_key,
            encoded_header,
            ciphertext,
            &[],
            &AeadTag::from_bytes(tag).unwrap(),
        )
        .unwrap();

        Message {
            sender: message_sender_bytes.try_into().unwrap(),
            receiver: mesage_receiver_bytes.try_into().unwrap(),
            header,
            secret_message: ciphertext,
        }
    }
}

pub fn setup() -> (Keypair, Keypair) {
    let mut csprng = StdRng::from_entropy();

    let (alice_private, alice_public) = KemType::gen_keypair(&mut csprng);
    let (bob_private, bob_public) = KemType::gen_keypair(&mut csprng);

    let alice_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
    let bob_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);

    let alice = Keypair {
        name: "alice".to_owned(),
        private_key: alice_private,
        public_key: alice_public,
        verifying_key: alice_signing_key.verifying_key(),
        signing_key: alice_signing_key,
    };

    let bob = Keypair {
        name: "bob".to_owned(),
        private_key: bob_private,
        public_key: bob_public,
        verifying_key: bob_signing_key.verifying_key(),
        signing_key: bob_signing_key,
    };

    (alice, bob)
}

#[cfg(test)]
mod tests {
    use hpke::Serializable;

    use super::{setup, Message};

    #[test]
    fn seal_unseal_message() {
        let (sender, receiver) = setup();
        let secret_message = b"hello world";
        let header = b"extra header data";

        let message = Message {
            sender: &sender.public_key.to_bytes().try_into().unwrap(),
            receiver: &receiver.public_key.to_bytes().try_into().unwrap(),
            header,
            secret_message,
        };

        let mut sealed = message.seal_hpke(&sender);
        let received_message = Message::unseal_hpke(&mut sealed, &receiver, &sender.verifying_key);

        assert_eq!(message, received_message);
    }
}
