use futures_util::StreamExt;
use rand::Rng;
use std::time::Duration;
use tokio::time::sleep;
use tsp_definitions::{Error, ResolvedVid};
use tsp_vid::VidController;

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
    let alice: &'static VidController = Box::leak(Box::new(
        VidController::from_file("./examples/test/alice.identity")
            .await
            .unwrap(),
    ));
    let bob: &'static VidController = Box::leak(Box::new(
        VidController::from_file("./examples/test/bob.identity")
            .await
            .unwrap(),
    ));

    for (me, you) in [(alice, bob), (bob, alice)] {
        tokio::spawn(async move {
            let stream = tsp::receive(me, None).unwrap();
            tokio::pin!(stream);

            loop {
                let message = match stream.next().await {
                    Some(Ok(m)) => m,
                    Some(Err(Error::UnexpectedRecipient)) => {
                        continue;
                    }
                    Some(Err(e)) => {
                        tracing::error!("{e}");
                        continue;
                    }
                    None => {
                        tracing::error!("connection closed");
                        break;
                    }
                };

                tracing::info!(
                    "{} decrypted {} from {}",
                    String::from_utf8_lossy(me.identifier()),
                    String::from_utf8_lossy(&message.payload),
                    String::from_utf8_lossy(message.sender.identifier())
                );
            }
        });

        tokio::spawn(async move {
            loop {
                let random_wait = rand::thread_rng().gen_range(0..2000);
                sleep(Duration::from_millis(2000 + random_wait)).await;
                let word = random_word::gen(random_word::Lang::En);

                tsp::send(me, you, None, word.as_bytes()).await.unwrap();

                tracing::info!(
                    "{} encrypted and sent {word} for {}",
                    String::from_utf8_lossy(me.identifier()),
                    String::from_utf8_lossy(you.identifier()),
                );
            }
        });
    }

    server_handle.await.unwrap();
}
