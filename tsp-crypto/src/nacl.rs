use std::io::Write;

use crypto_box::{
    aead::{generic_array::GenericArray, AeadCore, AeadMutInPlace},
    ChaChaBox, PublicKey, SecretKey,
};
use ed25519_dalek::Signer;
use rand::{rngs::StdRng, SeedableRng};

use crate::Message;

pub struct Sender {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
    pub signing_key: ed25519_dalek::SigningKey,
}

pub struct Receiver {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

impl Message<'_> {
    pub fn seal_nacl(&self, sender: &Sender) -> Vec<u8> {
        let mut csprng = StdRng::from_entropy();
        let mut data = self.serialize_header();

        let message_receiver = PublicKey::from(*self.receiver);

        let mut sender_box = ChaChaBox::new(&message_receiver, &sender.private_key);
        let nonce = ChaChaBox::generate_nonce(&mut csprng);
        let mut ciphertext = Vec::with_capacity(self.secret_message.len() + crypto_box::SEALBYTES);
        ciphertext.write_all(self.secret_message).unwrap();

        let tag = sender_box
            .encrypt_in_place_detached(&nonce, &[], &mut ciphertext)
            .expect("Could not encrypt");

        data.append(&mut ciphertext);
        data.extend_from_slice(&tag[..]);
        data.extend_from_slice(&nonce[..]);
        data.extend_from_slice(&sender.signing_key.sign(&data).to_bytes());

        data
    }

    pub fn unseal_nacl<'a>(data: &'a mut [u8], receiver: &Receiver) -> Message<'a> {
        let header_len = u16::from_be_bytes(data[..2].try_into().unwrap()) as usize;
        let signature_split = data.len() - 64;

        // verify outer signature
        let signature = ed25519_dalek::Signature::try_from(&data[signature_split..]).unwrap();
        receiver
            .verifying_key
            .verify_strict(&data[..signature_split], &signature)
            .unwrap();

        // decode message
        let (encoded_header, rest) = data.split_at_mut(header_len + 66);
        let message_sender_bytes: &[u8] = &encoded_header[2..34];
        let mesage_receiver_bytes: &[u8] = &encoded_header[34..66];

        // signature (64 bytes) + enc key (32 bytes) + tag (16 bytes)
        let (ciphertext, footer) = rest.split_at_mut(rest.len() - (64 + 16 + 24));
        let header = &encoded_header[66..];
        let (tag, nonce) = footer.split_at_mut(16);
        let tag = GenericArray::from_mut_slice(tag);
        let nonce = GenericArray::from_mut_slice(&mut nonce[0..24]);

        let sender_public_key: [u8; 32] = (*message_sender_bytes).try_into().unwrap();
        let message_sender = PublicKey::from(sender_public_key);
        let mut receiver_box = ChaChaBox::new(&message_sender, &receiver.private_key);

        receiver_box
            .decrypt_in_place_detached(nonce, &[], ciphertext, tag)
            .unwrap();

        Message {
            sender: message_sender_bytes.try_into().unwrap(),
            receiver: mesage_receiver_bytes.try_into().unwrap(),
            header,
            secret_message: ciphertext,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Message, Receiver, Sender};
    use crypto_box::SecretKey;
    use rand::{rngs::StdRng, SeedableRng};

    fn setup<'a>() -> (Sender, Receiver) {
        let mut csprng = StdRng::from_entropy();

        let sender_private = SecretKey::generate(&mut csprng);
        let receiver_private = SecretKey::generate(&mut csprng);

        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);

        let receiver = Receiver {
            public_key: receiver_private.public_key(),
            private_key: receiver_private,
            verifying_key: signing_key.verifying_key(),
        };

        let sender = Sender {
            public_key: sender_private.public_key(),
            private_key: sender_private,
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
            sender: &sender.public_key.to_bytes().try_into().unwrap(),
            receiver: &receiver.public_key.to_bytes().try_into().unwrap(),
            header,
            secret_message,
        };

        let mut sealed = message.seal_nacl(&sender);

        dbg!(&sealed);

        let received_message = Message::unseal_nacl(&mut sealed, &receiver);

        assert_eq!(message, received_message);
    }
}
