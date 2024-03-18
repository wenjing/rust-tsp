use async_recursion::async_recursion;
use futures::StreamExt;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{
    mpsc::{self, Receiver},
    RwLock,
};
use tsp_cesr::EnvelopeType;
use tsp_definitions::{Error, MessageType, Payload, ReceivedTspMessage, VerifiedVid};
use tsp_vid::{PrivateVid, Vid};

use crate::resolve_vid;

#[derive(Debug, Default)]
pub struct VidDatabase {
    private_vids: Arc<RwLock<HashMap<String, PrivateVid>>>,
    verified_vids: Arc<RwLock<HashMap<String, Vid>>>,
}

impl VidDatabase {
    pub fn new() -> Self {
        Default::default()
    }

    pub async fn add_private_vid(&self, private_vid: PrivateVid) -> Result<(), Error> {
        let mut private_vids = self.private_vids.write().await;
        private_vids.insert(private_vid.identifier().to_string(), private_vid);

        Ok(())
    }

    pub async fn add_verified_vid(&self, verified_vid: Vid) -> Result<(), Error> {
        let mut verified_vids = self.verified_vids.write().await;
        verified_vids.insert(verified_vid.identifier().to_string(), verified_vid);

        Ok(())
    }

    #[cfg(test)]
    pub async fn add_private_vid_from_file(&self, name: &str) -> Result<(), Error> {
        let private_vid = PrivateVid::from_file(format!("../examples/{name}")).await?;

        self.add_private_vid(private_vid).await
    }

    /// Resolve public key material for a VID and add it to the detabase as a relation
    pub async fn resolve_vid(&mut self, vid: &str) -> Result<(), Error> {
        let mut verified_vids = self.verified_vids.write().await;

        let resolved_vid = resolve_vid(vid).await?;
        verified_vids.insert(vid.to_string(), resolved_vid);

        Ok(())
    }

    /// Send a TSP message given earlier resolved VID's
    pub async fn send(
        &self,
        sender: &str,
        receiver: &str,
        nonconfidential_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<(), Error> {
        let sender = self.get_private_vid(sender).await?;
        let receiver = self.get_verified_vid(receiver).await?;

        let tsp_message = tsp_crypto::seal(
            &sender,
            &receiver,
            nonconfidential_data,
            Payload::Content(message),
        )?;
        tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

        Ok(())
    }

    pub async fn send_nested(
        &self,
        receiver: &str,
        nonconfidential_data: Option<&[u8]>,
        payload: Payload<&[u8]>,
    ) -> Result<(), Error> {
        let inner_receiver = self.get_verified_vid(receiver).await?;

        let (sender, receiver, inner_message) =
            match (inner_receiver.parent_vid(), inner_receiver.sender_vid()) {
                (Some(parent_receiver), Some(inner_sender)) => {
                    let inner_sender = self.get_private_vid(inner_sender).await?;
                    let tsp_message =
                        tsp_crypto::sign(&inner_sender, Some(&inner_receiver), payload)?;

                    match inner_sender.parent_vid() {
                        Some(parent_sender) => {
                            let parent_sender = self.get_private_vid(parent_sender).await?;
                            let parent_receiver = self.get_verified_vid(parent_receiver).await?;

                            (parent_sender, parent_receiver, tsp_message)
                        }
                        None => return Err(Error::InvalidVID("missing parent for inner VID")),
                    }
                }
                (None, _) => return Err(Error::InvalidVID("missing parent VID for receiver")),
                (_, None) => return Err(Error::InvalidVID("missing sender VID for receiver")),
            };

        let tsp_message = tsp_crypto::seal(
            &sender,
            &receiver,
            nonconfidential_data,
            Payload::NestedMessage(&inner_message),
        )?;

        tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

        Ok(())
    }

    async fn get_private_vid(&self, vid: &str) -> Result<PrivateVid, Error> {
        match self.private_vids.read().await.get(vid) {
            Some(resolved) => Ok(resolved.clone()),
            None => Err(Error::UnVerifiedVid(vid.to_string())),
        }
    }

    async fn get_verified_vid(&self, vid: &str) -> Result<Vid, Error> {
        match self.verified_vids.read().await.get(vid) {
            Some(resolved) => Ok(resolved.clone()),
            None => Err(Error::UnVerifiedVid(vid.to_string())),
        }
    }

    #[async_recursion]
    async fn decode_message(
        receiver: Arc<PrivateVid>,
        verified_vids: Arc<RwLock<HashMap<String, Vid>>>,
        message: &mut [u8],
    ) -> Result<ReceivedTspMessage<Vec<u8>, Vid>, Error> {
        let sniffed_message = tsp_cesr::probe(message)?;

        match sniffed_message {
            EnvelopeType::EncryptedMessage {
                sender,
                receiver: intended_receiver,
            } => {
                if intended_receiver != receiver.identifier().as_bytes() {
                    return Err(Error::UnexpectedRecipient);
                }

                let sender = std::str::from_utf8(sender)?;

                let Some(sender) = verified_vids.read().await.get(sender).cloned() else {
                    return Err(Error::UnVerifiedVid(sender.to_string()));
                };

                let (nonconfidential_data, payload) =
                    tsp_crypto::open(receiver.as_ref(), &sender, message)?;

                match payload {
                    Payload::Content(message) => Ok(ReceivedTspMessage::<Vec<u8>, Vid> {
                        sender,
                        nonconfidential_data: nonconfidential_data.map(|v| v.to_vec()),
                        message: Payload::Content(message.to_owned()),
                        message_type: MessageType::SignedAndEncrypted,
                    }),
                    Payload::NestedMessage(message) => {
                        // TODO: do not allocate
                        let mut inner = message.to_owned();
                        VidDatabase::decode_message(receiver, verified_vids, &mut inner).await
                    }
                    _ => Err(Error::UnexpectedControlMessage),
                }
            }
            EnvelopeType::SignedMessage {
                sender,
                receiver: intended_receiver,
            } => {
                if intended_receiver != Some(receiver.identifier().as_bytes()) {
                    return Err(Error::UnexpectedRecipient);
                }

                let sender = std::str::from_utf8(sender)?;

                let Some(sender) = verified_vids.read().await.get(sender).cloned() else {
                    return Err(Error::UnVerifiedVid(sender.to_string()));
                };

                let payload = tsp_crypto::verify(&sender, message)?;

                match payload {
                    Payload::Content(message) => Ok(ReceivedTspMessage::<Vec<u8>, Vid> {
                        sender,
                        nonconfidential_data: None,
                        message: Payload::Content(message.to_owned()),
                        message_type: MessageType::Signed,
                    }),
                    _ => Err(Error::UnexpectedControlMessage),
                }
            }
        }
    }

    /// Receive TSP messages given the receivers transport
    /// Messages will be queued in a channel
    /// The returned channel contains a maximum of 16 messages
    pub async fn receive(
        &self,
        vid: &str,
    ) -> Result<Receiver<Result<ReceivedTspMessage<Vec<u8>, Vid>, Error>>, Error> {
        let receiver = Arc::new(self.get_private_vid(vid).await?);
        let verified_vids = self.verified_vids.clone();
        let (tx, rx) = mpsc::channel(16);
        let messages = tsp_transport::receive_messages(receiver.endpoint())?;

        tokio::task::spawn(async move {
            let decrypted_messages = messages.then(move |data| {
                let receiver = receiver.clone();
                let verified_vids = verified_vids.clone();

                async move { Self::decode_message(receiver, verified_vids, &mut data?).await }
            });

            tokio::pin!(decrypted_messages);

            while let Some(m) = decrypted_messages.next().await {
                let _ = tx.send(m).await;
            }
        });

        Ok(rx)
    }

    pub async fn propose_nested_relationship(
        &self,
        _sender: &str,
        _receiver: &str,
    ) -> Result<(&str, &str), Error> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use crate::VidDatabase;
    use tsp_definitions::{Error, Payload};

    async fn test_alice_nested() -> Result<(), Error> {
        // alice database
        let mut db = VidDatabase::new();
        db.add_private_vid_from_file("test/alice.json").await?;
        db.resolve_vid("did:web:did.tsp-test.org:user:bob").await?;

        let _ = db.receive("did:web:did.tsp-test.org:user:alice").await?;

        let (_my_inner_vid, bobs_inner_vid) = db
            .propose_nested_relationship(
                "did:web:did.tsp-test.org:user:alice",
                "did:web:did.tsp-test.org:user:bob",
            )
            .await?;

        // send a message
        db.send_nested(bobs_inner_vid, None, Payload::Content(b"hello bob"))
            .await?;

        Ok(())
    }

    async fn test_bob_nested() -> Result<(), Error> {
        // bob database
        let mut db = VidDatabase::new();
        db.add_private_vid_from_file("test/bob.json").await?;
        db.resolve_vid("did:web:did.tsp-test.org:user:alice")
            .await?;

        let mut bobs_messages = db.receive("did:web:did.tsp-test.org:user:bob").await?;

        let _message = bobs_messages.recv().await.unwrap()?;
        // assert!(message.is_relationship_proposal());
        // let (my_vid, sender_vid) = db.accept_relationship(&message).await?;

        // let message = bobs_messages.recv().await.unwrap()?;
        // assert_eq!(message.payload, b"hello bob");

        Ok(())
    }

    async fn test_send_receive_nested() -> Result<(), tsp_definitions::Error> {
        let _bob_handle = tokio::task::spawn(test_bob_nested());
        let _alice_handle = tokio::task::spawn(test_alice_nested());

        // bob_handle.await.unwrap().unwrap();
        // alice_handle.await.unwrap().unwrap();

        Ok(())
    }

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
        let message = bobs_messages.recv().await.unwrap()?;
        assert_eq!(message.message, Payload::Content(b"hello world".to_vec()));

        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(tcp)]
    async fn vid_database() {
        tsp_transport::tcp::start_broadcast_server("127.0.0.1:1337")
            .await
            .unwrap();

        test_send_receive().await.unwrap();
        test_send_receive_nested().await.unwrap();
    }
}
