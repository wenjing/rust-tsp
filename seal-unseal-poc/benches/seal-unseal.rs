use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpke::{Kem, Serializable};
use rand::{rngs::StdRng, SeedableRng};
use seal_unseal_poc::{KemType, Message, Receiver, Sender};

fn seal_unseal_message(sender: &Sender, receiver: &Receiver, secret_message: &[u8], header: &[u8]) {
    let message = Message {
        sender: &sender.public_key.to_bytes().try_into().unwrap(),
        receiver: &receiver.public_key.to_bytes().try_into().unwrap(),
        header,
        secret_message,
    };

    let mut sealed = message.seal(&sender);
    let received_message = Message::unseal(&mut sealed, &receiver);

    assert_eq!(message, received_message);
}

fn criterion_benchmark(c: &mut Criterion) {
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

    c.bench_function("seal_unseal_message", |b| b.iter(|| seal_unseal_message(
        black_box(&sender),
        black_box(&receiver),
        black_box(b"hello world"),
        black_box(b"extra extra"),
    )));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
