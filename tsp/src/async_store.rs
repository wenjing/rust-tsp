use crate::{error::Error, store::Store, RelationshipStatus};
use futures::StreamExt;
use std::collections::HashMap;
use tokio::sync::mpsc::{self, Receiver};
use tsp_crypto::error::Error as CryptoError;
use tsp_definitions::{Digest, Payload, ReceivedTspMessage, VerifiedVid};
use tsp_vid::{error::Error as VidError, PrivateVid, Vid};

/// Holds private ands verified VID's
/// A Store contains verified vid's, our relationship status to them,
/// as well as the private vid's that this application has control over.
///
/// # Example
///
/// ```no_run
/// use tsp::{AsyncStore, PrivateVid, Error, ReceivedTspMessage};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Error> {
///     // alice database
///     let mut db = AsyncStore::new();
///     db.add_private_vid_from_file("test/alice.json").await?;
///     db.verify_vid("did:web:did.tsp-test.org:user:bob").await?;
///
///     // send a message
///     db.send(
///         "did:web:did.tsp-test.org:user:alice",
///         "did:web:did.tsp-test.org:user:bob",
///         Some(b"extra non-confidential data"),
///         b"hello world",
///     ).await?;
///
///     Ok(())
/// }
/// ```
#[derive(Default)]
pub struct AsyncStore {
    inner: Store,
}

impl AsyncStore {
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a private nested VID identified by `vid` that can be used for nested relationships. If `relation_vid`
    /// is `Some(other_vid)`, this private VID will be associated with that `other_vid`.
    /// Currently only supports one level of nesting. The nested vid must have the did:peer format.
    pub fn create_private_nested_vid(
        &self,
        vid: &str,
        relation_vid: Option<&str>,
    ) -> Result<String, Error> {
        self.inner.create_private_nested_vid(vid, relation_vid)
    }

    /// Adds a relation to an already existing vid, making it a nested Vid
    pub fn set_relation_for_vid(&self, vid: &str, relation_vid: Option<&str>) -> Result<(), Error> {
        self.inner.set_relation_for_vid(vid, relation_vid)
    }

    /// Adds a route to an already existing vid, making it a nested Vid
    pub fn set_route_for_vid(&self, vid: &str, route: &[&str]) -> Result<(), Error> {
        self.inner.set_route_for_vid(vid, route)
    }

    /// Adds `private_vid` to the database
    pub fn add_private_vid(&self, private_vid: PrivateVid) -> Result<(), Error> {
        self.inner.add_private_vid(private_vid)
    }

    /// Add the already resolved `verified_vid` to the database as a relationship
    pub fn add_verified_vid(&self, verified_vid: Vid) -> Result<(), Error> {
        self.inner.add_verified_vid(verified_vid)
    }

    /// Export the database as a tuple of private and verified VID's
    pub fn export(&self) -> Result<(Vec<PrivateVid>, Vec<Vid>), Error> {
        self.inner.export()
    }

    /// Check whether the [PrivateVid] identified by `vid` exists inthe database
    pub fn has_private_vid(&self, vid: &str) -> Result<bool, Error> {
        self.inner.has_private_vid(vid)
    }

    /// Adds a private VID to the database from a file (JSON encoded)
    pub async fn add_private_vid_from_file(&self, name: &str) -> Result<(), Error> {
        let private_vid = PrivateVid::from_file(format!("../examples/{name}")).await?;

        self.inner.add_private_vid(private_vid)
    }

    /// Resolve and verify public key material for a VID identified by `vid` and add it to the database as a relationship
    pub async fn verify_vid(&mut self, vid: &str) -> Result<(), Error> {
        let verified_vid = tsp_vid::verify_vid(vid).await?;

        self.inner
            .verified_vids
            .write()?
            .insert(vid.to_string(), verified_vid);

        Ok(())
    }

    /// Resolve and verify public key material for a VID identified by `vid`, and add it to the database as with `verify_vid`, but also
    /// specify that its parent is the publically known VID identified by `parent_vid` (that must already be resolved).
    /// If `relation_vid` is not `None`, use the provided vid (which must resolve to a private vid) as our local nested VID that
    /// will have a relationship with `vid`.
    pub async fn verify_vid_with_parent(
        &mut self,
        vid: &str,
        parent_vid: &str,
        relation_vid: Option<&str>,
    ) -> Result<(), Error> {
        let mut verified_vid = tsp_vid::verify_vid(vid).await?;

        verified_vid.set_parent_vid(parent_vid.to_string());
        verified_vid.set_relation_vid(relation_vid);

        self.inner
            .verified_vids
            .write()?
            .insert(vid.to_string(), verified_vid);

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
    /// use tsp::{AsyncStore, PrivateVid};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut db = AsyncStore::new();
    ///     let private_vid = PrivateVid::from_file(format!("../examples/test/bob.json")).await.unwrap();
    ///     db.add_private_vid(private_vid).unwrap();
    ///     db.verify_vid("did:web:did.tsp-test.org:user:alice").await.unwrap();
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
    ) -> Result<Vec<u8>, Error> {
        let sender = self.inner.get_private_vid(sender)?;
        let receiver = self.inner.get_verified_vid(receiver)?;

        let tsp_message = tsp_crypto::seal(
            &sender,
            &receiver,
            nonconfidential_data,
            Payload::Content(message),
        )?;

        tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

        Ok(tsp_message)
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
    /// use tsp::{AsyncStore, PrivateVid};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut db = AsyncStore::new();
    ///     let private_vid = PrivateVid::from_file(format!("../examples/test/bob.json")).await.unwrap();
    ///     db.add_private_vid(private_vid).unwrap();
    ///     db.verify_vid("did:web:did.tsp-test.org:user:alice").await.unwrap();
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
        let sender = self.inner.get_private_vid(sender)?;
        let receiver = self.inner.get_verified_vid(receiver)?;

        let (tsp_message, thread_id) =
            tsp_crypto::seal_and_hash(&sender, &receiver, None, Payload::RequestRelationship)?;

        tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

        self.inner.relation_status.write()?.insert(
            receiver.identifier().to_string(),
            RelationshipStatus::Unidirectional(thread_id),
        );

        Ok(())
    }

    /// Accept a direct relationship between the resolved VID's identifier by `sender` and `receiver`.
    /// `thread_id` must be the same as the one that was present in the relationship request.
    /// Encodes the control message, encrypts, signs and sends a TSP message
    pub async fn send_relationship_accept(
        &self,
        sender: &str,
        receiver: &str,
        thread_id: Digest,
    ) -> Result<(), Error> {
        let sender = self.inner.get_private_vid(sender)?;
        let receiver = self.inner.get_verified_vid(receiver)?;

        let tsp_message = tsp_crypto::seal(
            &sender,
            &receiver,
            None,
            Payload::AcceptRelationship { thread_id },
        )?;
        tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

        self.inner.relation_status.write()?.insert(
            receiver.identifier().to_string(),
            RelationshipStatus::Bidirectional(thread_id),
        );

        Ok(())
    }

    /// Cancels a direct relationship between the resolved `sender` and `receiver` VID's.
    /// Encodes the control message, encrypts, signs and sends a TSP message
    pub async fn send_relationship_cancel(
        &self,
        sender: &str,
        receiver: &str,
    ) -> Result<(), Error> {
        let sender = self.inner.get_private_vid(sender)?;
        let receiver = self.inner.get_verified_vid(receiver)?;

        self.inner.relation_status.write()?.insert(
            receiver.identifier().to_string(),
            RelationshipStatus::Unrelated,
        );

        let thread_id = Default::default(); // FNORD

        let tsp_message = tsp_crypto::seal(
            &sender,
            &receiver,
            None,
            Payload::CancelRelationship { thread_id },
        )?;
        tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

        Ok(())
    }

    /// Send a nested TSP message given earlier resolved VID's: `receiver` is recipient. Since this must indicate a resolved
    /// nested VID, this message will be sent with our related private VID as an origin. As with the direct [fn send] method,
    /// `nonconfidential_data` is data that is sent in the clear (signed but not encrypted), `message` is the confidential
    /// message (signed and encrypted).
    pub async fn send_nested(
        &self,
        receiver: &str,
        nonconfidential_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<(), Error> {
        let inner_receiver = self.inner.get_verified_vid(receiver)?;

        let (sender, receiver, inner_message) =
            match (inner_receiver.parent_vid(), inner_receiver.relation_vid()) {
                (Some(parent_receiver), Some(inner_sender)) => {
                    let inner_sender = self.inner.get_private_vid(inner_sender)?;
                    let tsp_message =
                        tsp_crypto::sign(&inner_sender, Some(&inner_receiver), message)?;

                    match inner_sender.parent_vid() {
                        Some(parent_sender) => {
                            let parent_sender = self.inner.get_private_vid(parent_sender)?;
                            let parent_receiver = self.inner.get_verified_vid(parent_receiver)?;

                            (parent_sender, parent_receiver, tsp_message)
                        }
                        None => {
                            return Err(VidError::ResolveVid("missing parent for inner VID").into())
                        }
                    }
                }
                (None, _) => {
                    return Err(VidError::ResolveVid("missing parent VID for receiver").into())
                }
                (_, None) => {
                    return Err(VidError::ResolveVid("missing sender VID for receiver").into())
                }
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

    /// Send a E2E-routed TSP `message` given earlier resolved VID's.
    /// The message is routed through the route that has been established with `receiver`.
    /// The `intermediary_extra_data` is "non-confidential data" that is not visible to the outside
    /// world, but can be seen by every intermediary node.
    pub async fn send_routed(
        &self,
        receiver: &str,
        intermediary_extra_data: Option<&[u8]>,
        message: &[u8],
    ) -> Result<(), Error> {
        let inner_receiver = self.inner.get_verified_vid(receiver)?;

        let Some(intermediaries) = inner_receiver.get_route() else {
            return Err(VidError::ResolveVid("no route established for VID").into());
        };

        let first_hop = self.inner.get_verified_vid(&intermediaries[0])?;

        let (sender, inner_message) =
            match (first_hop.relation_vid(), inner_receiver.relation_vid()) {
                (Some(first_sender), Some(inner_sender)) => {
                    let inner_sender = self.inner.get_private_vid(inner_sender)?;
                    let tsp_message = tsp_crypto::seal(
                        &inner_sender,
                        &inner_receiver,
                        intermediary_extra_data,
                        Payload::Content(message),
                    )?;

                    let first_sender = self.inner.get_private_vid(first_sender)?;

                    (first_sender, tsp_message)
                }
                (None, _) => {
                    return Err(VidError::ResolveVid("missing sender VID for first hop").into())
                }
                (_, None) => {
                    return Err(VidError::ResolveVid("missing sender VID for receiver").into())
                }
            };

        //TODO: is collect necessary here?
        let hops = intermediaries[1..]
            .iter()
            .map(|x| x.as_ref())
            .collect::<Vec<_>>();

        let tsp_message = tsp_crypto::seal(
            &sender,
            &first_hop,
            None,
            Payload::RoutedMessage(hops, &inner_message),
        )?;

        tsp_transport::send_message(first_hop.endpoint(), &tsp_message).await?;

        Ok(())
    }

    // Receive, open and forward a TSP message
    pub async fn route_message(
        &self,
        sender: &str,
        receiver: &str,
        message: &mut [u8],
    ) -> Result<(), Error> {
        let Ok(receiver) = self.inner.get_private_vid(receiver) else {
            return Err(CryptoError::UnexpectedRecipient.into());
        };

        let Ok(sender) = self.inner.get_verified_vid(sender) else {
            return Err(Error::UnverifiedVid(sender.to_string()));
        };

        let (_, payload, _) = tsp_crypto::open(&receiver, &sender, message)?;

        let Payload::RoutedMessage(hops, inner_message) = payload else {
            return Err(Error::InvalidRoute("expected a routed message".to_string()));
        };

        let next_hop = std::str::from_utf8(hops[0])?;

        let Ok(next_hop) = self.inner.get_verified_vid(next_hop) else {
            return Err(Error::UnverifiedVid(next_hop.to_string()));
        };

        let path = hops[1..].to_vec();

        self.forward_routed_message(next_hop.identifier(), path, inner_message)
            .await
    }

    /// Pass along a in-transit routed TSP `opaque_message` that is not meant for us, given earlier resolved VID's.
    /// The message is routed through the route that has been established with `receiver`.
    pub async fn forward_routed_message(
        &self,
        next_hop: &str,
        path: Vec<&[u8]>,
        opaque_message: &[u8],
    ) -> Result<(), Error> {
        let (destination, tsp_message) = if path.is_empty() {
            // we are the final delivery point, we should be the 'next_hop'
            let sender = self.inner.get_private_vid(next_hop)?;

            //TODO: we cannot user 'sender.relation_vid()', since the relationship status of this cannot be set
            let recipient = match self
                .inner
                .get_verified_vid(sender.identifier())?
                .relation_vid()
            {
                Some(destination) => self.inner.get_verified_vid(destination)?,
                None => return Err(VidError::ResolveVid("no relation for drop-off VID").into()),
            };

            let tsp_message = tsp_crypto::seal(
                &sender,
                &recipient,
                None,
                Payload::NestedMessage(opaque_message),
            )?;

            (recipient, tsp_message)
        } else {
            // we are an intermediary, continue sending the message
            let next_hop = self.inner.get_verified_vid(next_hop)?;

            let sender = match next_hop.relation_vid() {
                Some(first_sender) => self.inner.get_private_vid(first_sender)?,
                None => return Err(VidError::ResolveVid("missing sender VID for first hop").into()),
            };

            let tsp_message = tsp_crypto::seal(
                &sender,
                &next_hop,
                None,
                Payload::RoutedMessage(path, opaque_message),
            )?;

            (next_hop, tsp_message)
        };

        tsp_transport::send_message(destination.endpoint(), &tsp_message).await?;

        Ok(())
    }

    /// Receive TSP messages for the private VID identified by `vid`, using the appropriate transport mechanism for it.
    /// Messages will be queued in a channel
    /// The returned channel contains a maximum of 16 messages
    pub async fn receive(
        &self,
        vid: &str,
    ) -> Result<Receiver<Result<ReceivedTspMessage<Vid>, Error>>, Error> {
        let mut receiver = self.inner.get_private_vid(vid)?;
        let mut receivers = HashMap::new();

        loop {
            receivers.insert(receiver.identifier().to_string(), receiver.clone());

            match receiver.parent_vid() {
                Some(parent_vid) => {
                    receiver = self.inner.get_private_vid(parent_vid)?;
                }
                _ => break,
            }
        }

        let (tx, rx) = mpsc::channel(16);
        let mut messages = tsp_transport::receive_messages(receiver.endpoint()).await?;

        let db = self.inner.clone();
        tokio::task::spawn(async move {
            while let Some(message) = messages.next().await {
                let result = match message {
                    Ok(mut m) => db.clone().decode_message(&mut m),
                    Err(e) => Err(e.into()),
                };

                let _ = tx.send(result).await;
            }
        });

        Ok(rx)
    }
}
