use futures::StreamExt;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{
    mpsc::{self, Receiver},
    RwLock,
};
use tsp_definitions::{Error, Payload, ReceivedTspMessage, VerifiedVid};
use tsp_vid::{PrivateVid, Vid};

use crate::resolve_vid;

#[derive(Debug, Default)]
pub struct VidDatabase {
    identities: Arc<RwLock<HashMap<String, PrivateVid>>>,
    relations: Arc<RwLock<HashMap<String, Vid>>>,
}

impl VidDatabase {
    pub fn new() -> Self {
        Default::default()
    }

    pub async fn add_private_vid(&self, private_vid: PrivateVid) -> Result<(), Error> {
        let mut identities = self.identities.write().await;

        let key = std::str::from_utf8(private_vid.identifier())?;
        identities.insert(key.to_string(), private_vid);

        Ok(())
    }

    #[cfg(test)]
    pub async fn add_private_vid_from_file(&self, name: &str) -> Result<(), Error> {
        let private_vid = PrivateVid::from_file(format!("../examples/{name}")).await?;

        self.add_private_vid(private_vid).await
    }

    /// Resolve public key material for a VID and add it to the detabase as a relation
    pub async fn resolve_vid(&mut self, vid: &str) -> Result<(), Error> {
        let mut relations = self.relations.write().await;

        let resolved_vid = resolve_vid(vid).await?;
        relations.insert(vid.to_string(), resolved_vid);

        Ok(())
    }

    /// Send a TSP message given earlier resolved VID's
    pub async fn send(
        &self,
        sender_vid: &str,
        receiver_vid: &str,
        nonconfidential_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<(), Error> {
        let sender = self.get_private_vid(sender_vid).await?;
        let receiver = self.get_verified_vid(receiver_vid).await?;

        let tsp_message = tsp_crypto::seal(
            &sender,
            &receiver,
            nonconfidential_data,
            Payload::Content(message),
        )?;
        tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

        Ok(())
    }

    async fn get_private_vid(&self, vid: &str) -> Result<PrivateVid, Error> {
        match self.identities.read().await.get(vid) {
            Some(resolved) => Ok(resolved.clone()),
            None => Err(Error::UnVerifiedVid(vid.to_string())),
        }
    }

    async fn get_verified_vid(&self, vid: &str) -> Result<Vid, Error> {
        match self.relations.read().await.get(vid) {
            Some(resolved) => Ok(resolved.clone()),
            None => Err(Error::UnVerifiedVid(vid.to_string())),
        }
    }

    /// Receive TSP messages given the receivers transport
    /// Messages will be queued in a channel
    /// The returned channel contains a maximum of 16 messages
    pub async fn receive(
        &self,
        vid: &str,
    ) -> Result<Receiver<Result<ReceivedTspMessage<Vid>, Error>>, Error> {
        let receiver = Arc::new(self.get_private_vid(vid).await?);
        let relations = self.relations.clone();
        let (tx, rx) = mpsc::channel(16);
        let messages = tsp_transport::receive_messages(receiver.endpoint())?;

        tokio::task::spawn(async move {
            let decrypted_messages = messages.then(move |data| {
                let receiver = receiver.clone();
                let relations = relations.clone();

                async move {
                    let mut message = data?;

                    let (sender, intended_receiver) = tsp_cesr::get_sender_receiver(&mut message)?;

                    if intended_receiver != receiver.identifier() {
                        return Err(Error::UnexpectedRecipient);
                    }

                    let sender = std::str::from_utf8(sender)?;

                    let Some(sender) = relations.read().await.get(sender).cloned() else {
                        return Err(Error::UnVerifiedVid(sender.to_string()));
                    };

                    let (nonconfidential_data, payload) =
                        tsp_crypto::open(receiver.as_ref(), &sender, &mut message)?;

                    match payload {
                        Payload::Content(message) => {
                            Ok(ReceivedTspMessage::<Vid>::GenericMessage {
                                sender,
                                nonconfidential_data: nonconfidential_data.map(|v| v.to_vec()),
                                message: message.to_owned(),
                            })
                        }
                        _ => unimplemented!("control messages are not supported at this level yet"),
                    }
                }
            });

            tokio::pin!(decrypted_messages);

            while let Some(m) = decrypted_messages.next().await {
                let _ = tx.send(m).await;
            }
        });

        Ok(rx)
    }
}

#[cfg(test)]
mod test {
    use crate::VidDatabase;

    async fn test_send_receive() -> Result<(), tsp_definitions::Error> {
        // bob database
        let mut db1 = VidDatabase::new();
        db1.add_private_vid_from_file("test/bob.json").await?;
        db1.resolve_vid("did:web:did.tsp-test.org:user:alice")
            .await?;

        let mut bobs_messages = db1.receive("did:web:did.tsp-test.org:user:bob").await?;

        // alice database
        let mut db2 = VidDatabase::new();
        db2.add_private_vid_from_file("test/alice.json").await?;
        db2.resolve_vid("did:web:did.tsp-test.org:user:bob").await?;

        // send a message
        db2.send(
            "did:web:did.tsp-test.org:user:alice",
            "did:web:did.tsp-test.org:user:bob",
            Some(b"extra non-confidential data"),
            b"hello world",
        )
        .await?;

        // receive a message
        let tsp_definitions::ReceivedTspMessage::GenericMessage { message, .. } =
            bobs_messages.recv().await.unwrap()?;
        assert_eq!(message, b"hello world");

        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(tcp)]
    async fn vid_database() {
        tsp_transport::tcp::start_broadcast_server("127.0.0.1:1337")
            .await
            .unwrap();

        test_send_receive().await.unwrap();
    }
}
