use ed25519_dalek::Signer;
use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
};
use rand::{rngs::StdRng, SeedableRng};
use std::io::Write;

type KemType = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;

type PrivateKey = <KemType as Kem>::PrivateKey;
type PublicKey = <KemType as Kem>::PublicKey;

pub struct Sender<'a> {
    pub signing_key: ed25519_dalek::SigningKey,
    pub op_mode: OpModeS<'a, KemType>,
}

pub struct Receiver {
    pub private_key: PrivateKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Message<'a> {
    sender: PublicKey,
    receiver: PublicKey,
    secret_message: &'a [u8],
}

impl Message<'_> {
    pub fn serialize_header(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::with_capacity(64);

        result.write_all(&self.sender.to_bytes()).unwrap();
        result.write_all(&self.receiver.to_bytes()).unwrap();

        result
    }

    pub fn seal(&self, sender: &Sender) -> Vec<u8> {
        let mut csprng = StdRng::from_entropy();
        let mut data = self.serialize_header();

        let mut ciphertext = self.secret_message.to_vec();

        let (encapped_key, tag) =
            hpke::single_shot_seal_in_place_detached::<Aead, Kdf, KemType, StdRng>(
                &sender.op_mode,
                &self.receiver,
                &self.sender.to_bytes(),
                &mut ciphertext,
                &data,
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

    pub fn unseal<'a>(data: &'a mut [u8], receiver: &Receiver) -> Message<'a> {
        let signature_split = data.len() - 64;

        // verify outer signature
        let signature = ed25519_dalek::Signature::try_from(&data[signature_split..]).unwrap();
        receiver
            .verifying_key
            .verify_strict(&data[..signature_split], &signature)
            .unwrap();

        // decode message
        let (header, rest) = data.split_at_mut(64);
        let (ciphertext, footer) = rest.split_at_mut(rest.len() - (64 + 32 + 16));
        let message_sender_bytes = &header[0..32];
        let mesage_receiver_bytes = &header[32..64];
        let tag = &footer[0..16];
        let encapped_key = &footer[16..(16 + 32)];
        let message_sender = PublicKey::from_bytes(message_sender_bytes).unwrap();
        let message_receiver = PublicKey::from_bytes(mesage_receiver_bytes).unwrap();
        let encapped_key = <KemType as Kem>::EncappedKey::from_bytes(encapped_key).unwrap();

        hpke::single_shot_open_in_place_detached::<Aead, Kdf, KemType>(
            &OpModeR::Auth(message_sender.clone()),
            &receiver.private_key,
            &encapped_key,
            message_sender_bytes,
            ciphertext,
            header,
            &AeadTag::from_bytes(tag).unwrap(),
        )
        .unwrap();

        Message {
            sender: message_sender,
            receiver: message_receiver,
            secret_message: ciphertext,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{KemType, Message, PublicKey, Receiver, Sender};
    use hpke::{Kem, OpModeS};
    use rand::{rngs::StdRng, SeedableRng};

    fn setup<'a>() -> (Sender<'a>, Receiver, PublicKey, PublicKey) {
        let mut csprng = StdRng::from_entropy();

        let (sender_private, sender_public) = KemType::gen_keypair(&mut csprng);
        let (receiver_private, receiver_public) = KemType::gen_keypair(&mut csprng);

        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);

        let receiver = Receiver {
            private_key: receiver_private,
            verifying_key: signing_key.verifying_key(),
        };

        let sender = Sender {
            signing_key,
            op_mode: OpModeS::Auth((sender_private, sender_public.clone())),
        };

        (sender, receiver, sender_public, receiver_public)
    }

    #[test]
    fn seal_unseal_message() {
        let (sender, receiver, sender_public, receiver_public) = setup();
        let secret_message = b"hello world".to_vec();

        let message = Message {
            sender: sender_public,
            receiver: receiver_public,
            secret_message: &secret_message,
        };

        let mut sealed = message.seal(&sender);

        assert_eq!(sealed.len(), 187);

        let received_message = Message::unseal(&mut sealed, &receiver);

        assert_eq!(message, received_message);
    }
}
