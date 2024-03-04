use async_stream::try_stream;
use futures::{Stream, StreamExt};
use std::collections::HashMap;
use tokio::sync::{mpsc, RwLock};
use tsp_definitions::{Error, ReceivedTspMessage, ResolvedVid};
use tsp_vid::{Vid, VidController};

use crate::resolve_vid;

#[derive(Debug, Default)]
pub struct VidDatabase {
    identities: RwLock<HashMap<String, VidController>>,
    relations: RwLock<HashMap<String, Vid>>,
}

impl VidDatabase {
    const CHANNEL_SIZE: usize = 16;

    pub fn new() -> Self {
        Default::default()
    }

    pub async fn receive(
        &self,
        vid: &str,
    ) -> Result<mpsc::Receiver<ReceivedTspMessage<Vid>>, Error> {
        let messages = self.receive_inner(vid).await?;
        let (tx, rx) = mpsc::channel(Self::CHANNEL_SIZE);
        tokio::pin!(messages);

        while let Some(message) = messages.next().await {
            match message {
                Ok(message) => {
                    if let Err(_e) = tx.send(message).await {
                        // TODO: log send error
                    }
                }
                Err(_) => {
                    // TODO: log error
                }
            };
        }

        Ok(rx)
    }

    async fn receive_inner(
        &self,
        vid: &str,
    ) -> Result<impl Stream<Item = Result<ReceivedTspMessage<Vid>, Error>> + '_, Error> {
        let identities = self.identities.read().await;

        let Some(receiver) = identities.get(vid).cloned() else {
            return Err(Error::UnresolvedVid(vid.to_string()));
        };

        Ok(try_stream! {
            let messages = tsp_transport::receive_messages(receiver.endpoint())?;
            tokio::pin!(messages);

            while let Some(m) = messages.next().await {
                let mut message = m?;

                let (sender, intended_receiver) = tsp_cesr::get_sender_receiver(&mut message)?;

                if intended_receiver != receiver.identifier() {
                    Err(Error::UnexpectedRecipient)?
                }

                let sender = std::str::from_utf8(sender)?;
                let relations = self.relations.read().await;

                let Some(sender) = relations.get(sender) else {
                    Err(Error::UnresolvedVid(sender.to_string()))?
                };

                let (nonconfidential_data, payload) = tsp_crypto::open(&receiver, sender, &mut message)?;

                yield ReceivedTspMessage::<Vid> {
                    sender: sender.clone(),
                    nonconfidential_data: nonconfidential_data.map(|v| v.to_vec()),
                    payload: payload.to_owned(),
                };
            }
        })
    }

    pub async fn add_identity(&self, vid_controller: VidController) {
        let mut identities = self.identities.write().await;
        let key = String::from_utf8_lossy(vid_controller.identifier());
        identities.insert(key.to_string(), vid_controller);
    }

    pub async fn resolve_vid(&self, vid: &str) -> Result<(), Error> {
        let mut relations = self.relations.write().await;
        let resolved_vid = resolve_vid(vid).await?;
        relations.insert(vid.to_string(), resolved_vid);

        Ok(())
    }

    pub async fn send(
        &self,
        sender_vid: &str,
        receiver_vid: &str,
        nonconfidential_data: Option<&[u8]>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let identities = self.identities.read().await;

        let Some(sender) = identities.get(sender_vid) else {
            return Err(Error::UnresolvedVid(sender_vid.to_string()));
        };

        let relations = self.relations.read().await;

        let Some(receiver) = relations.get(receiver_vid) else {
            return Err(Error::UnresolvedVid(receiver_vid.to_string()));
        };

        let tsp_message = tsp_crypto::seal(sender, receiver, nonconfidential_data, payload)?;
        tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use tokio::sync::oneshot;

    use crate::VidDatabase;

    #[ignore]
    #[tokio::test]
    async fn vid_database() {
        let address = "127.0.0.1:1337";
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn(async move {
            tsp_transport::tcp::broadcast_server(address, Some(tx))
                .await
                .unwrap();
        });
        rx.await.unwrap();

        let alice = tsp_vid::VidController::from_file("../examples/test/alice.identity")
            .await
            .unwrap();
        let bob = tsp_vid::VidController::from_file("../examples/test/bob.identity")
            .await
            .unwrap();

        let bob_db = VidDatabase::new();
        bob_db.add_identity(bob).await;
        bob_db
            .resolve_vid("did:web:did.tweede.golf:user:alice")
            .await
            .unwrap();
        let mut bob_receiver = bob_db
            .receive("did:web:did.tweede.golf:user:bob")
            .await
            .unwrap();

        let alice_db = VidDatabase::new();
        alice_db.add_identity(alice).await;
        alice_db
            .resolve_vid("did:web:did.tweede.golf:user:bob")
            .await
            .unwrap();
        alice_db
            .send(
                "did:web:did.tweede.golf:user:alice",
                "did:web:did.tweede.golf:user:bob",
                None,
                b"hello world",
            )
            .await
            .unwrap();

        let message = bob_receiver.recv().await.unwrap();

        dbg!(message);
    }
}
