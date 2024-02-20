use std::time::Duration;

use hpke::Serializable;
use rand::Rng;
use tokio::{io::AsyncWriteExt, time::sleep};
use tokio_util::{codec::{BytesCodec, Framed}, sync::CancellationToken};
use tsp_crypto::Message;
use tokio_stream::StreamExt;

const SERVER_ADDRESS: &str = "127.0.0.1:1337";

async fn send(msg: &[u8]) {
    let mut stream = tokio::net::TcpStream::connect(SERVER_ADDRESS)
        .await
        .unwrap();

    stream.write_all(msg).await.unwrap();
}

#[tokio::main]
async fn main() {
    // start broadcast server
    let token = CancellationToken::new();
    let server_handle = tokio::spawn(async move {
        tsp_transport::tcp::broadcast_server(SERVER_ADDRESS).await.unwrap();
    });

    // wait for server to start
    sleep(Duration::from_secs(2)).await;

    // setup crypto
    let (alice, bob) = tsp_crypto::hpke::setup();

    for (me, other) in [(alice.clone(), bob.clone()), (bob, alice)] {
        let (reveiver_me, receiver_other) = (me.clone(), other.clone());
        tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(SERVER_ADDRESS)
                .await
                .unwrap();

            let mut messages = Framed::new(stream, BytesCodec::new());

            let pk_bytes = reveiver_me.public_key.to_bytes().to_vec();

            loop {
                let mut message = match messages.next().await {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => {
                        tracing::error!("{e}");
                        continue;
                    }
                    None => {
                        break;
                    }
                };

                // check thge message was intended for us
                if message[34..66] != pk_bytes {
                    continue;
                }

                tracing::info!(
                    "{} received {} from {}",
                    reveiver_me.name,
                    const_hex::encode(&message),
                    receiver_other.name
                );

                let message: Message = Message::unseal_hpke(
                    &mut message,
                    &reveiver_me,
                    &receiver_other.verifying_key,
                );

                tracing::info!(
                    "{} decrypted {} from {}",
                    reveiver_me.name,
                    String::from_utf8_lossy(message.secret_message),
                    receiver_other.name
                );
            }
        });

        let cloned_token = token.clone();
        tokio::spawn(async move {
            loop {
                let random_wait = rand::thread_rng().gen_range(0..2000);

                tokio::select! {
                    _ = sleep(Duration::from_millis(2000 + random_wait)) => {}
                    _ = cloned_token.cancelled() => {
                        return;
                    }
                };

                let word = random_word::gen(random_word::Lang::En);
                let ciphertext = Message {
                    sender: &hpke::Serializable::to_bytes(&me.public_key).into(),
                    receiver: &hpke::Serializable::to_bytes(&other.public_key).into(),
                    header: &[],
                    secret_message: word.as_bytes(),
                }
                .seal_hpke(&me);

                send(&ciphertext).await;
                tracing::info!("{} encrypted {word} for {}", me.name, other.name);
                tracing::info!(
                    "{} sent {} to {}",
                    me.name,
                    const_hex::encode(&ciphertext),
                    other.name
                );
            }
        });
    }

    server_handle.await.unwrap();
}
