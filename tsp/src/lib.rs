use async_recursion::async_recursion;
use futures::StreamExt;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{
    mpsc::{self, Receiver},
    RwLock,
};
use tsp_cesr::EnvelopeType;
use tsp_definitions::{Digest, Error, MessageType, Payload, ReceivedTspMessage, VerifiedVid};
use tsp_vid::{PrivateVid, Vid};

/// Holds private ands verified VID's
#[derive(Debug, Default)]
/// A VidDatabase contains verified vid's, our relationship status to them,
/// as well as the private vid's that this application has control over.
pub struct VidDatabase {
    private_vids: Arc<RwLock<HashMap<String, PrivateVid>>>,
    verified_vids: Arc<RwLock<HashMap<String, Vid>>>,
}

/// This database is used to store and resolve VID's
impl VidDatabase {
    /// Create a new, empty VID database
    pub fn new() -> Self {
        Default::default()
    }

    /// Adds [private_vid] to the database
    pub async fn add_private_vid(&self, private_vid: PrivateVid) -> Result<(), Error> {
        let mut private_vids = self.private_vids.write().await;
        private_vids.insert(private_vid.identifier().to_string(), private_vid);

        Ok(())
    }

    /// Creates a private nested VID identified by [vid] that can be used for nested relationships. If [relation_vid]
    /// is `Some(other_vid)`, this private VID will be associated with that `other_vid`.
    /// Currently only supports one level of nesting. The nested vid must have the did:peer format.
    // TODO: Split this function into a 'create private nested vid' and 'add relationship to vid' ?
    pub async fn create_private_nested_vid(
        &self,
        vid: &str,
        relation_vid: Option<&str>,
    ) -> Result<String, Error> {
        let nested = match self.private_vids.read().await.get(vid) {
            Some(resolved) => resolved.create_nested(relation_vid),
            None => return Err(Error::UnverifiedVid(vid.to_string())),
        };

        let id = nested.identifier().to_string();
        self.add_private_vid(nested).await?;

        Ok(id)
    }

    /// Add the already resolved [verified_vid] to the database as a relationship
    pub async fn add_verified_vid(&self, verified_vid: Vid) -> Result<(), Error> {
        let mut verified_vids = self.verified_vids.write().await;
        verified_vids.insert(verified_vid.identifier().to_string(), verified_vid);

        Ok(())
    }

    /// Adds a private VID to the database from a file
    #[cfg(test)]
    pub async fn add_private_vid_from_file(&self, name: &str) -> Result<(), Error> {
        let private_vid = PrivateVid::from_file(format!("../examples/{name}")).await?;

        self.add_private_vid(private_vid).await
    }

    /// Resolve public key material for a VID identified by [vid] and add it to the database as a relationship
    pub async fn resolve_vid(&mut self, vid: &str) -> Result<(), Error> {
        let mut verified_vids = self.verified_vids.write().await;

        let resolved_vid = tsp_vid::resolve_vid(vid).await?;
        verified_vids.insert(vid.to_string(), resolved_vid);

        Ok(())
    }

    /// Resolve public key material for a VID identified by [vid], and add it to the database as with [resolve_vid], but also
    /// specify that its parent is the publically known VID identified by [parent_vid] (that must already be resolved).
    /// If [relation_vid] is not `None`, use the provided vid (which must resolve to a private vid) as our local nested VID that
    /// will have a relationship with [vid].
    pub async fn resolve_vid_with_parent(
        &mut self,
        vid: &str,
        parent_vid: &str,
        relation_vid: Option<&str>,
    ) -> Result<(), Error> {
        let mut verified_vids = self.verified_vids.write().await;

        let mut resolved_vid = tsp_vid::resolve_vid(vid).await?;

        resolved_vid.set_parent_vid(parent_vid.to_string());
        resolved_vid.set_relation_vid(relation_vid);
        verified_vids.insert(vid.to_string(), resolved_vid);

        Ok(())
    }

    /// Send a TSP message given earlier resolved VID's
    /// Encodes, encrypts, signs and sends a TSP message
    ///
    /// # Arguments
    ///
    /// * `sender`               - A sender VID
    /// * `receiver`             - A receiver VID
    /// * `nonconfidential_data` - Optional extra non-confidential data
    /// * `payload`              - The raw message payload as byte slice
    ///
    /// # Example
    ///
    /// ```
    /// use tsp::VidDatabase;
    /// use tsp_vid::PrivateVid;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut db = VidDatabase::new();
    ///     let private_vid = PrivateVid::from_file(format!("../examples/test/bob.json")).await.unwrap();
    ///     db.add_private_vid(private_vid).await.unwrap();
    ///     db.resolve_vid("did:web:did.tsp-test.org:user:alice").await.unwrap();
    ///
    ///     let sender = "did:web:did.tsp-test.org:user:bob";
    ///     let receiver = "did:web:did.tsp-test.org:user:alice";
    ///
    ///     let result = db.send(sender, receiver, None, b"hello world").await;
    /// }
    /// ```
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

    /// Request a direct relationship with a resolved VID using the TSP
    /// Encodes the control message, encrypts, signs and sends a TSP message
    ///
    /// # Arguments
    ///
    /// * `sender`               - A sender VID
    /// * `receiver`             - A receiver VID
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tsp::VidDatabase;
    /// use tsp_vid::PrivateVid;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut db = VidDatabase::new();
    ///     let private_vid = PrivateVid::from_file(format!("../examples/test/bob.json")).await.unwrap();
    ///     db.add_private_vid(private_vid).await.unwrap();
    ///     db.resolve_vid("did:web:did.tsp-test.org:user:alice").await.unwrap();
    ///
    ///     let sender = "did:web:did.tsp-test.org:user:bob";
    ///     let receiver = "did:web:did.tsp-test.org:user:alice";
    ///
    ///     let result = db.send_relationship_request(sender, receiver).await;
    /// }
    /// ```
    pub async fn send_relationship_request(
        &self,
        sender: &str,
        receiver: &str,
    ) -> Result<(), Error> {
        let sender = self.get_private_vid(sender).await?;
        let receiver = self.get_verified_vid(receiver).await?;

        let tsp_message = tsp_crypto::seal(&sender, &receiver, None, Payload::RequestRelationship)?;
        tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

        //TODO: record the thread-id of the message we sent
        Ok(())
    }

    /// Accept a direct relationship between the resolved VID's identifier by [sender] and [receiver].
    /// [thread_id] must be the same as the one that was present in the relationship request.
    /// Encodes the control message, encrypts, signs and sends a TSP message
    pub async fn send_relationship_accept(
        &self,
        sender: &str,
        receiver: &str,
        thread_id: Digest,
    ) -> Result<(), Error> {
        let sender = self.get_private_vid(sender).await?;
        let receiver = self.get_verified_vid(receiver).await?;

        let tsp_message = tsp_crypto::seal(
            &sender,
            &receiver,
            None,
            Payload::AcceptRelationship { thread_id },
        )?;
        tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

        Ok(())
    }

    /// Cancels a direct relationship between the resolved [sender] and [receiver] VID's.
    /// Encodes the control message, encrypts, signs and sends a TSP message
    pub async fn send_relationship_cancel(
        &self,
        sender: &str,
        receiver: &str,
    ) -> Result<(), Error> {
        let sender = self.get_private_vid(sender).await?;
        let receiver = self.get_verified_vid(receiver).await?;

        let tsp_message = tsp_crypto::seal(&sender, &receiver, None, Payload::CancelRelationship)?;
        tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

        Ok(())
    }

    /// Send a nested TSP message given earlier resolved VID's: [receiver] is recipient. Since this must indicate a resolved
    /// nested VID, this message will be sent with our related private VID as an origin. As with the direct [send] method,
    /// [nonconfidential_data] is data that is sent in the clear (signed but not encrypted), [message] is the confidential
    /// message (signed and encrypted).
    pub async fn send_nested(
        &self,
        receiver: &str,
        nonconfidential_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<(), Error> {
        let inner_receiver = self.get_verified_vid(receiver).await?;

        let (sender, receiver, inner_message) =
            match (inner_receiver.parent_vid(), inner_receiver.relation_vid()) {
                (Some(parent_receiver), Some(inner_sender)) => {
                    let inner_sender = self.get_private_vid(inner_sender).await?;
                    let tsp_message =
                        tsp_crypto::sign(&inner_sender, Some(&inner_receiver), message)?;

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

    /// Retrieve the [PrivateVid] identified by [vid] from the database, if it exists.
    async fn get_private_vid(&self, vid: &str) -> Result<PrivateVid, Error> {
        match self.private_vids.read().await.get(vid) {
            Some(resolved) => Ok(resolved.clone()),
            None => Err(Error::UnverifiedVid(vid.to_string())),
        }
    }

    /// Retrieve the [Vid] identified by [vid] from the database, if it exists.
    async fn get_verified_vid(&self, vid: &str) -> Result<Vid, Error> {
        match self.verified_vids.read().await.get(vid) {
            Some(resolved) => Ok(resolved.clone()),
            None => Err(Error::UnverifiedVid(vid.to_string())),
        }
    }

    /// Decode an encrypted [message], which has to be addressed to one of the VID's in [receivers], and has to have
    /// [verified_vids] as one of the senders.
    #[async_recursion]
    async fn decode_message(
        receivers: Arc<HashMap<String, PrivateVid>>,
        verified_vids: Arc<RwLock<HashMap<String, Vid>>>,
        message: &mut [u8],
    ) -> Result<ReceivedTspMessage<Vid>, Error> {
        let probed_message = tsp_cesr::probe(message)?;

        match probed_message {
            EnvelopeType::EncryptedMessage {
                sender,
                receiver: intended_receiver,
            } => {
                let intended_receiver = std::str::from_utf8(intended_receiver)?;

                let Some(intended_receiver) = receivers.get(intended_receiver) else {
                    return Err(Error::UnexpectedRecipient);
                };

                let sender = std::str::from_utf8(sender)?;

                let Some(sender) = verified_vids.read().await.get(sender).cloned() else {
                    return Err(Error::UnverifiedVid(sender.to_string()));
                };

                let (nonconfidential_data, payload, raw_bytes) =
                    tsp_crypto::open(intended_receiver, &sender, message)?;

                match payload {
                    Payload::Content(message) => Ok(ReceivedTspMessage::<Vid>::GenericMessage {
                        sender,
                        nonconfidential_data: nonconfidential_data.map(|v| v.to_vec()),
                        message: message.to_owned(),
                        message_type: MessageType::SignedAndEncrypted,
                    }),
                    Payload::NestedMessage(message) => {
                        // TODO: do not allocate
                        let mut inner = message.to_owned();
                        VidDatabase::decode_message(receivers, verified_vids, &mut inner).await
                    }
                    Payload::RequestRelationship => Ok(ReceivedTspMessage::RequestRelationship {
                        sender,
                        thread_id: tsp_crypto::sha256(raw_bytes),
                    }),
                    // TODO: check the digest and record that we have this relationship
                    Payload::AcceptRelationship { thread_id: _digest } => {
                        //TODO: if the thread_id is invalid, don't send this response
                        Ok(ReceivedTspMessage::AcceptRelationship { sender })
                    }
                    // TODO: record that we have to end this relationship
                    Payload::CancelRelationship => {
                        Ok(ReceivedTspMessage::CancelRelationship { sender })
                    }
                }
            }
            EnvelopeType::SignedMessage {
                sender,
                receiver: intended_receiver,
            } => {
                if let Some(intended_receiver) = intended_receiver {
                    let intended_receiver = std::str::from_utf8(intended_receiver)?;

                    if !receivers.contains_key(intended_receiver) {
                        return Err(Error::UnexpectedRecipient);
                    }
                };

                let sender = std::str::from_utf8(sender)?;

                let Some(sender) = verified_vids.read().await.get(sender).cloned() else {
                    return Err(Error::UnverifiedVid(sender.to_string()));
                };

                let payload = tsp_crypto::verify(&sender, message)?;

                Ok(ReceivedTspMessage::<Vid>::GenericMessage {
                    sender,
                    nonconfidential_data: None,
                    message: payload.to_owned(),
                    message_type: MessageType::Signed,
                })
            }
        }
    }

    /// Receive TSP messages for the private VID identified by [vid], using the appropriate transport mechanism for it.
    /// Messages will be queued in a channel
    /// The returned channel contains a maximum of 16 messages
    // TODO: is it useful to specify multiple receivers here?
    pub async fn receive(
        &self,
        vid: &str,
    ) -> Result<Receiver<Result<ReceivedTspMessage<Vid>, Error>>, Error> {
        let mut receiver = self.get_private_vid(vid).await?;
        let mut receivers = HashMap::new();

        loop {
            receivers.insert(receiver.identifier().to_string(), receiver.clone());

            match receiver.parent_vid() {
                Some(parent_vid) => {
                    receiver = self.get_private_vid(parent_vid).await?;
                }
                _ => break,
            }
        }

        let receivers = Arc::new(receivers);
        let verified_vids = self.verified_vids.clone();
        let (tx, rx) = mpsc::channel(16);
        let messages = tsp_transport::receive_messages(receiver.endpoint()).await?;

        tokio::task::spawn(async move {
            let decrypted_messages = messages.then(move |data| {
                let receivers = receivers.clone();
                let verified_vids = verified_vids.clone();

                async move { Self::decode_message(receivers, verified_vids, &mut data?).await }
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

    #[tokio::test]
    #[serial_test::serial(tcp)]
    async fn test_direct_mode() {
        tsp_transport::tcp::start_broadcast_server("127.0.0.1:1337")
            .await
            .unwrap();

        // bob database
        let mut bob_db = VidDatabase::new();
        bob_db
            .add_private_vid_from_file("test/bob.json")
            .await
            .unwrap();
        bob_db
            .resolve_vid("did:web:did.tsp-test.org:user:alice")
            .await
            .unwrap();

        let mut bobs_messages = bob_db
            .receive("did:web:did.tsp-test.org:user:bob")
            .await
            .unwrap();

        // alice database
        let mut alice_db = VidDatabase::new();
        alice_db
            .add_private_vid_from_file("test/alice.json")
            .await
            .unwrap();
        alice_db
            .resolve_vid("did:web:did.tsp-test.org:user:bob")
            .await
            .unwrap();

        // send a message
        alice_db
            .send(
                "did:web:did.tsp-test.org:user:alice",
                "did:web:did.tsp-test.org:user:bob",
                Some(b"extra non-confidential data"),
                b"hello world",
            )
            .await
            .unwrap();

        // receive a message
        let tsp_definitions::ReceivedTspMessage::GenericMessage { message, .. } =
            bobs_messages.recv().await.unwrap().unwrap()
        else {
            panic!("bob did not receive a generic message")
        };

        assert_eq!(message, b"hello world");
    }

    #[tokio::test]
    #[serial_test::serial(tcp)]
    async fn test_nested_mode() {
        tsp_transport::tcp::start_broadcast_server("127.0.0.1:1337")
            .await
            .unwrap();

        // bob database
        let mut bob_db = VidDatabase::new();
        bob_db
            .add_private_vid_from_file("test/bob.json")
            .await
            .unwrap();
        bob_db
            .resolve_vid("did:web:did.tsp-test.org:user:alice")
            .await
            .unwrap();

        // alice database
        let mut alice_db = VidDatabase::new();
        alice_db
            .add_private_vid_from_file("test/alice.json")
            .await
            .unwrap();
        alice_db
            .resolve_vid("did:web:did.tsp-test.org:user:bob")
            .await
            .unwrap();

        // create nested id's
        let nested_bob_vid = bob_db
            .create_private_nested_vid("did:web:did.tsp-test.org:user:bob", None)
            .await
            .unwrap();

        // receive a messages on inner vid
        let mut bobs_inner_messages = bob_db.receive(&nested_bob_vid).await.unwrap();

        let nested_alice_vid = alice_db
            .create_private_nested_vid("did:web:did.tsp-test.org:user:alice", Some(&nested_bob_vid))
            .await
            .unwrap();

        alice_db
            .resolve_vid_with_parent(
                &nested_bob_vid,
                "did:web:did.tsp-test.org:user:bob",
                Some(&nested_alice_vid),
            )
            .await
            .unwrap();

        bob_db.resolve_vid(&nested_alice_vid).await.unwrap();

        // send a message using inner vid
        alice_db
            .send_nested(
                &nested_bob_vid,
                Some(b"extra non-confidential data"),
                b"hello nested world",
            )
            .await
            .unwrap();

        // receive message using inner vid
        let tsp_definitions::ReceivedTspMessage::GenericMessage { message, .. } =
            bobs_inner_messages.recv().await.unwrap().unwrap()
        else {
            panic!("bob did not receive a generic message inner")
        };

        assert_eq!(message, b"hello nested world".to_vec());
    }

    async fn faulty_send(
        sender: &impl tsp_definitions::Sender,
        receiver: &impl tsp_definitions::VerifiedVid,
        nonconfidential_data: Option<&[u8]>,
        message: &[u8],
        corrupt: impl FnOnce(&mut [u8]),
    ) -> Result<(), super::Error> {
        let mut tsp_message = tsp_crypto::seal(
            sender,
            receiver,
            nonconfidential_data,
            super::Payload::Content(message),
        )?;
        corrupt(&mut tsp_message);
        tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

        Ok(())
    }

    #[tokio::test]
    #[serial_test::serial(tcp)]
    async fn attack_failures() {
        tsp_transport::tcp::start_broadcast_server("127.0.0.1:1337")
            .await
            .unwrap();

        // bob database
        let mut bob_db = VidDatabase::new();
        bob_db
            .add_private_vid_from_file("test/bob.json")
            .await
            .unwrap();
        bob_db
            .resolve_vid("did:web:did.tsp-test.org:user:alice")
            .await
            .unwrap();

        let mut bobs_messages = bob_db
            .receive("did:web:did.tsp-test.org:user:bob")
            .await
            .unwrap();

        let alice = tsp_vid::PrivateVid::from_file("../examples/test/alice.json")
            .await
            .unwrap();

        let bob = tsp_vid::resolve_vid("did:web:did.tsp-test.org:user:bob")
            .await
            .unwrap();

        let payload = b"hello world";

        let mut stop = false;
        for i in 0.. {
            faulty_send(&alice, &bob, None, payload, |data| {
                if i >= data.len() {
                    stop = true
                } else {
                    data[i] ^= 0x10
                }
            })
            .await
            .unwrap();

            assert!(bobs_messages.recv().await.unwrap().is_err());

            if stop {
                break;
            }
        }
    }
}
