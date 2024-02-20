use std::time::Duration;

use hpke::Serializable;
use rand::Rng;
use tokio::{io::AsyncWriteExt, signal, time::sleep};
use tokio_util::sync::CancellationToken;
use tsp_crypto::Message;

async fn send(msg: &[u8]) {
    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:1337")
        .await
        .unwrap();

    stream.write_all(msg).await.unwrap();
}

#[tokio::main]
async fn main() {
    // start broadcast server
    let token = CancellationToken::new();
    let server_token = token.clone();
    let server_handle = tokio::spawn(async move {
        tsp_transport::tcp::broadcast_server(server_token)
            .await
            .unwrap();
    });

    // wait for server to start
    sleep(Duration::from_secs(2)).await;

    // setup crypto
    let (alice, bob) = tsp_crypto::hpke::setup();

    for (me, other) in [(alice.clone(), bob.clone()), (bob, alice)] {
        let receiver_token = token.clone();
        let (reveiver_me, receiver_other) = (me.clone(), other.clone());
        tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect("127.0.0.1:1337")
                .await
                .unwrap();

            let pk_bytes = reveiver_me.public_key.to_bytes().to_vec();

            loop {
                tokio::select! {
                    _ = stream.readable() => {

                        let mut buf = [0; 4096];
                        let n = match stream.try_read(&mut buf) {
                            Ok(0) => continue,
                            Ok(n) => n,
                            Err(ref e) if e.kind() == tokio::io::ErrorKind::WouldBlock => {
                                continue;
                            }
                            Err(e) => {
                                tracing::error!("{e}");
                                return;
                            }
                        };

                        // check thge message was intended for us
                        if buf[34..66] != pk_bytes {
                            continue;
                        }

                        tracing::info!(
                            "{} received {} from {}",
                            reveiver_me.name,
                            const_hex::encode(&buf[0..n]),
                            receiver_other.name
                        );

                        let message: Message = Message::unseal_hpke(&mut buf[0..n], &reveiver_me, &receiver_other.verifying_key);

                        tracing::info!(
                            "{} decrypted {} from {}",
                            reveiver_me.name,
                            String::from_utf8_lossy(message.secret_message),
                            receiver_other.name
                        );
                    }
                    _ = receiver_token.cancelled() => {
                        return;
                    }
                };
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

    // handle shutdown
    tokio::spawn(async move {
        signal::ctrl_c().await.unwrap();
        token.cancel();
    });
    server_handle.await.unwrap();
}
