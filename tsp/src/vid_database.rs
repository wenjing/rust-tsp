use futures::StreamExt;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{
    mpsc::{self, Receiver},
    RwLock,
};
use tsp_definitions::{Error, ReceivedTspMessage, ResolvedVid};
use tsp_vid::{Vid, VidController};

use crate::resolve_vid;

#[derive(Debug, Default)]
pub struct VidDatabase {
    identities: Arc<RwLock<HashMap<String, VidController>>>,
    relations: Arc<RwLock<HashMap<String, Vid>>>,
}

impl VidDatabase {
    pub fn new() -> Self {
        Default::default()
    }

    pub async fn add_identity(&self, vid_controller: VidController) -> Result<(), Error> {
        let mut identities = self.identities.write().await;

        let key = std::str::from_utf8(vid_controller.identifier())?;
        identities.insert(key.to_string(), vid_controller);

        Ok(())
    }

    #[cfg(test)]
    pub async fn add_identity_from_file(&self, name: &str) -> Result<(), Error> {
        let identity = VidController::from_file(format!("../examples/{name}")).await?;

        self.add_identity(identity).await
    }

    pub async fn resolve_vid(&mut self, vid: &str) -> Result<(), Error> {
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
        let sender = self.get_identity(sender_vid).await?;
        let receiver = self.get_relation(receiver_vid).await?;

        let tsp_message = tsp_crypto::seal(&sender, &receiver, nonconfidential_data, payload)?;
        tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

        Ok(())
    }

    async fn get_identity(&self, vid: &str) -> Result<VidController, Error> {
        match self.identities.read().await.get(vid) {
            Some(resolved) => Ok(resolved.clone()),
            None => Err(Error::UnresolvedVid(vid.to_string())),
        }
    }

    async fn get_relation(&self, vid: &str) -> Result<Vid, Error> {
        match self.relations.read().await.get(vid) {
            Some(resolved) => Ok(resolved.clone()),
            None => Err(Error::UnresolvedVid(vid.to_string())),
        }
    }

    pub async fn receive(
        &self,
        vid: &str,
    ) -> Result<Receiver<Result<ReceivedTspMessage<Vid>, Error>>, Error> {
        let receiver = self.get_identity(vid).await?;
        let relations = self.relations.clone();
        let (tx, rx) = mpsc::channel(16);

        tokio::task::spawn(async move {
            let messages = tsp_transport::receive_messages(receiver.endpoint()).unwrap();
            tokio::pin!(messages);

            while let Some(m) = messages.next().await {
                let mut message = match m {
                    Ok(m) => m,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        continue;
                    }
                };

                let (sender, intended_receiver) = match tsp_cesr::get_sender_receiver(&mut message)
                {
                    Ok(m) => m,
                    Err(e) => {
                        let _ = tx.send(Err(e.into())).await;
                        continue;
                    }
                };

                if intended_receiver != receiver.identifier() {
                    let _ = tx.send(Err(Error::UnexpectedRecipient)).await;
                    continue;
                }

                let sender = match std::str::from_utf8(sender) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = tx.send(Err(e.into())).await;
                        continue;
                    }
                };

                let sender = match relations.read().await.get(sender) {
                    Some(s) => s.clone(),
                    None => {
                        let _ = tx.send(Err(Error::UnresolvedVid(sender.to_string()))).await;
                        continue;
                    }
                };

                let (nonconfidential_data, payload) =
                    match tsp_crypto::open(&receiver, &sender, &mut message) {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                            continue;
                        }
                    };

                let _ = tx
                    .send(Ok(ReceivedTspMessage::<Vid> {
                        sender: sender.clone(),
                        nonconfidential_data: nonconfidential_data.map(|v| v.to_vec()),
                        payload: payload.to_owned(),
                    }))
                    .await;
            }

            // explicitly close the channel
            drop(tx);
        });

        Ok(rx)
    }
}

#[cfg(test)]
mod test {
    use tsp_definitions::{Error, ReceivedTspMessage};
    use tsp_vid::Vid;

    use crate::VidDatabase;

    async fn setup_alice_bob() -> Result<ReceivedTspMessage<Vid>, Error> {
        let mut db1 = VidDatabase::new();
        db1.add_identity_from_file("test/bob.identity").await?;
        db1.resolve_vid("did:web:did.tweede.golf:user:alice")
            .await?;

        let mut bobs_messages = db1.receive("did:web:did.tweede.golf:user:bob").await?;

        let mut db2 = VidDatabase::new();
        db2.add_identity_from_file("test/alice.identity").await?;
        db2.resolve_vid("did:web:did.tweede.golf:user:bob").await?;

        db2.send(
            "did:web:did.tweede.golf:user:alice",
            "did:web:did.tweede.golf:user:bob",
            Some(b"extra non-confidential data"),
            b"hello world",
        )
        .await?;

        bobs_messages.recv().await.unwrap()
    }

    #[tokio::test]
    #[serial_test::serial(tcp)]
    async fn vid_database() {
        tsp_transport::tcp::start_broadcast_server("127.0.0.1:1337")
            .await
            .unwrap();

        let message = setup_alice_bob().await.unwrap();

        assert_eq!(message.payload, b"hello world");
    }
}
