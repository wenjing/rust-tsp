use futures_util::{pin_mut, StreamExt};
use rand::Rng;
use std::time::Duration;
use tokio::time::sleep;
use tsp_crypto::dummy::Dummy;
use tsp_definitions::Error;

const SERVER_ADDRESS: &str = "127.0.0.1:1337";

#[tokio::main]
async fn main() {
    let (tx, rx) = tokio::sync::oneshot::channel();

    // start broadcast server
    let server_handle = tokio::spawn(async move {
        tsp_transport::tcp::broadcast_server(SERVER_ADDRESS, Some(tx))
            .await
            .unwrap();
    });

    // wait for server to start
    rx.await.unwrap();

    // setup crypto
    let (alice, bobbi) = (Dummy::new("alice"), Dummy::new("bobbi"));

    for (me, other) in [(alice.clone(), bobbi.clone()), (bobbi, alice)] {
        let (receiver_me, receiver_other) = (me.clone(), other.clone());
        tokio::spawn(async move {
            let stream = tsp::receive(&receiver_me, None);
            pin_mut!(stream);

            loop {
                let message = match stream.next().await {
                    Some(Ok(m)) => m,
                    Some(Err(Error::UnexpectedRecipient)) => {
                        //pass
                        continue;
                    }
                    Some(Err(e)) => {
                        tracing::error!("{e}");
                        continue;
                    }
                    None => {
                        break;
                    }
                };

                tracing::info!(
                    "{} decrypted {} from {}",
                    receiver_me.name(),
                    String::from_utf8_lossy(&message.payload),
                    receiver_other.name()
                );
            }
        });

        tokio::spawn(async move {
            loop {
                let random_wait = rand::thread_rng().gen_range(0..2000);
                sleep(Duration::from_millis(2000 + random_wait)).await;
                let word = random_word::gen(random_word::Lang::En);

                tsp::send(&me, &other, None, word.as_bytes()).await.unwrap();

                tracing::info!(
                    "{} encrypted and sent {word} for {}",
                    me.name(),
                    other.name()
                );
            }
        });
    }

    server_handle.await.unwrap();
}
