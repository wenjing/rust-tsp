use std::time::Duration;

use rand::Rng;
use tokio::{io::AsyncWriteExt, time::sleep};
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, Framed};
use tsp_crypto::dummy::Dummy;
use tsp_definitions::ResolvedVid;

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
    let server_handle = tokio::spawn(async move {
        tsp_transport::tcp::broadcast_server(SERVER_ADDRESS)
            .await
            .unwrap();
    });

    // wait for server to start
    sleep(Duration::from_secs(2)).await;

    // setup crypto
    let (alice, bobbi) = (Dummy::new("alice"), Dummy::new("bobbi"));

    for (me, other) in [(alice.clone(), bobbi.clone()), (bobbi, alice)] {
        let (receiver_me, receiver_other) = (me.clone(), other.clone());
        tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(SERVER_ADDRESS)
                .await
                .unwrap();

            let mut messages = Framed::new(stream, BytesCodec::new());

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

                // check the message was not sent by us
                if String::from_utf8_lossy(&message[7..(7 + receiver_me.vid().len())])
                    == receiver_me.name()
                {
                    continue;
                }

                tracing::info!(
                    "{} received {} bytes from {}",
                    receiver_me.name(),
                    message.len(),
                    receiver_other.name()
                );

                match tsp_crypto::open(&receiver_me, &receiver_other, &mut message) {
                    Ok((_, payload)) => {
                        tracing::info!(
                            "{} decrypted {} from {}",
                            receiver_me.name(),
                            String::from_utf8_lossy(payload),
                            receiver_other.name()
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "{} encountered an error decrypting from {} {e:?}",
                            receiver_me.name(),
                            receiver_other.name()
                        );
                    }
                }
            }
        });

        tokio::spawn(async move {
            loop {
                let random_wait = rand::thread_rng().gen_range(0..2000);
                sleep(Duration::from_millis(2000 + random_wait)).await;

                let word = random_word::gen(random_word::Lang::En);
                let ciphertext = match tsp_crypto::seal(&me, &other, None, word.as_bytes()) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("error encrypting a message {e}");
                        continue;
                    }
                };

                send(&ciphertext).await;
                tracing::info!("{} encrypted {word} for {}", me.name(), other.name());
                tracing::info!(
                    "{} sent {} bytes to {}",
                    me.name(),
                    ciphertext.len(),
                    other.name()
                );
            }
        });
    }

    server_handle.await.unwrap();
}
