use futures_util::StreamExt;
use rand::Rng;
use std::time::Duration;
use tokio::time::sleep;
use tsp_definitions::{Error, ReceivedTspMessage::*, VerifiedVid};
use tsp_transport::tcp::start_broadcast_server;
use tsp_vid::PrivateVid;

#[tokio::main]
async fn main() {
    // start broadcast server
    let server_handle = start_broadcast_server("127.0.0.1:1337").await.unwrap();

    // setup crypto
    let alice: &'static PrivateVid = Box::leak(Box::new(
        PrivateVid::from_file("./examples/test/alice.json")
            .await
            .unwrap(),
    ));
    let bob: &'static PrivateVid = Box::leak(Box::new(
        PrivateVid::from_file("./examples/test/bob.json")
            .await
            .unwrap(),
    ));

    for (me, you) in [(alice, bob), (bob, alice)] {
        tokio::spawn(async move {
            let stream = tsp::receive(me, None).await.unwrap();
            tokio::pin!(stream);

            loop {
                let received = match stream.next().await {
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

                let (sender, message) = match &received {
                    GenericMessage {
                        sender, message, ..
                    } => (sender, message.as_slice()),
                    RequestRelationship { sender, .. } => (sender, &b"{NEW_REL}"[..]),
                    AcceptRelationship { sender } => (sender, &b"{NEW_REL_REPLY}"[..]),
                    CancelRelationship { sender } => (sender, &b"{REL_CANCEL}"[..]),
                };

                tracing::info!(
                    "{} decrypted {} from {}",
                    me.identifier(),
                    String::from_utf8_lossy(message),
                    sender.identifier()
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
                    me.identifier(),
                    you.identifier(),
                );
            }
        });
    }

    server_handle.await.unwrap();
}
