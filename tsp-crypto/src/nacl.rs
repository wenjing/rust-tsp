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

use tsp_cesr::{DecodedEnvelope, Payload};

impl Message<'_> {
    pub fn seal_nacl(&self, sender: &Sender) -> Vec<u8> {
        let mut csprng = StdRng::from_entropy();
        let mut data = self.cesr_header();

        let message_receiver = PublicKey::from(*self.receiver);

        let mut sender_box = ChaChaBox::new(&message_receiver, &sender.private_key);
        let nonce = ChaChaBox::generate_nonce(&mut csprng);
        let mut ciphertext = Vec::with_capacity(self.secret_message.len() + crypto_box::SEALBYTES);
        tsp_cesr::encode_payload(Payload::HpkeMessage(self.secret_message), &mut ciphertext)
            .unwrap();

        let tag = sender_box
            .encrypt_in_place_detached(&nonce, &[], &mut ciphertext)
            .expect("Could not encrypt");

        ciphertext.extend_from_slice(&tag[..]);
        ciphertext.extend_from_slice(&nonce[..]);

        tsp_cesr::encode_ciphertext(&ciphertext, &mut data).expect("encoding error");

        let signature = sender.signing_key.sign(&data).to_bytes();
        tsp_cesr::encode_signature(&signature, &mut data);

        data
    }

    pub fn unseal_nacl<'a>(data: &'a mut [u8], receiver: &Receiver) -> Message<'a> {
        let decoded = tsp_cesr::decode_envelope_mut(data).expect("envelope");

        // verify outer signature
        let signature = ed25519_dalek::Signature::from(decoded.as_challenge().signature);
        receiver
            .verifying_key
            .verify_strict(decoded.as_challenge().signed_data, &signature)
            .unwrap();

        let DecodedEnvelope {
            envelope,
            ciphertext,
            ..
        } = decoded.into_opened::<&[u8; 32]>().unwrap();

        // signature (64 bytes) + enc key (32 bytes) + tag (16 bytes)
        let cipher_len = ciphertext.len();
        let (ciphertext, footer) = ciphertext.split_at_mut(cipher_len - (16 + 24));

        let (tag, nonce) = footer.split_at_mut(16);
        let tag = GenericArray::from_mut_slice(tag);
        let nonce = GenericArray::from_mut_slice(&mut nonce[0..24]);

        let message_sender = PublicKey::from(*envelope.sender);
        let mut receiver_box = ChaChaBox::new(&message_sender, &receiver.private_key);

        receiver_box
            .decrypt_in_place_detached(nonce, &[], ciphertext, tag)
            .unwrap();

        let Payload::HpkeMessage(secret_message) =
            tsp_cesr::decode_payload(ciphertext).expect("message");

        Message {
            sender: envelope.sender,
            receiver: envelope.receiver,
            header: envelope.nonconfidential_header.unwrap(),
            // will fix this later, as this defeats the purpose of in-place decryption
            secret_message,
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
