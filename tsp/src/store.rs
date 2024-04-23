use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tsp_cesr::EnvelopeType;
use tsp_crypto::error::Error as CryptoError;
use tsp_definitions::{MessageType, Payload};

pub use crate::error::Error;
use crate::RelationshipStatus;
pub use tsp_definitions::{ReceivedTspMessage, VerifiedVid};
pub use tsp_vid::{PrivateVid, Vid};

/// Holds private ands verified VID's
/// A Store contains verified vid's, our relationship status to them,
/// as well as the private vid's that this application has control over.
#[derive(Debug, Default, Clone)]
//TODO: refactor into a single HashMap<String, {vid+status}>, since being a 'PrivateVid' is also in some sense a "status"; also see gh #94
pub struct Store {
    pub(crate) private_vids: Arc<RwLock<HashMap<String, PrivateVid>>>,
    pub(crate) verified_vids: Arc<RwLock<HashMap<String, Vid>>>,
    pub(crate) relation_status: Arc<RwLock<HashMap<String, RelationshipStatus>>>,
}

/// This database is used to store and resolve VID's
impl Store {
    /// Create a new, empty VID database
    pub fn new() -> Self {
        Default::default()
    }

    /// Adds `private_vid` to the database
    pub fn add_private_vid(&self, private_vid: PrivateVid) -> Result<(), Error> {
        let mut private_vids = self.private_vids.write()?;
        private_vids.insert(private_vid.identifier().to_string(), private_vid);

        Ok(())
    }

    /// Creates a private nested VID identified by `vid` that can be used for nested relationships. If `relation_vid`
    /// is `Some(other_vid)`, this private VID will be associated with that `other_vid`.
    /// Currently only supports one level of nesting. The nested vid must have the did:peer format.
    // TODO: Split this function into a 'create private nested vid' and 'add relationship to vid' ?
    pub fn create_private_nested_vid(
        &self,
        vid: &str,
        relation_vid: Option<&str>,
    ) -> Result<String, Error> {
        let nested = match self.private_vids.read()?.get(vid) {
            Some(resolved) => resolved.create_nested(relation_vid),
            None => return Err(Error::UnverifiedVid(vid.to_string())),
        };

        let id = nested.identifier().to_string();
        self.add_private_vid(nested)?;

        Ok(id)
    }

    /// Adds a relation to an already existing vid, making it a nested Vid
    pub fn set_relation_for_vid(&self, vid: &str, relation_vid: Option<&str>) -> Result<(), Error> {
        self.modify_verified_vid(vid, |resolved| {
            resolved.set_relation_vid(relation_vid);

            Ok(())
        })
    }

    /// Adds a route to an already existing vid, making it a nested Vid
    pub fn set_route_for_vid(&self, vid: &str, route: &[&str]) -> Result<(), Error> {
        if route.len() == 1 {
            return Err(Error::InvalidRoute(
                "A route must have at least two VID's".into(),
            ));
        }
        self.modify_verified_vid(vid, |resolved| {
            resolved.set_route(route);

            Ok(())
        })
    }

    /// Add the already resolved `verified_vid` to the database as a relationship
    pub fn add_verified_vid(&self, verified_vid: Vid) -> Result<(), Error> {
        let mut verified_vids = self.verified_vids.write()?;
        verified_vids.insert(verified_vid.identifier().to_string(), verified_vid);

        Ok(())
    }

    /// Export the database as a tuple of private and verified VID's
    pub fn export(&self) -> Result<(Vec<PrivateVid>, Vec<Vid>), Error> {
        let private_vids = self.private_vids.read()?.values().cloned().collect();
        let verified_vids = self.verified_vids.read()?.values().cloned().collect();

        Ok((private_vids, verified_vids))
    }

    /// Check whether the [PrivateVid] identified by `vid` exists inthe database
    pub fn has_private_vid(&self, vid: &str) -> Result<bool, Error> {
        Ok(self.private_vids.read()?.contains_key(vid))
    }

    /// Modify a verified-vid by applying an operation to it (internal use only)
    pub(crate) fn modify_verified_vid(
        &self,
        vid: &str,
        change: impl FnOnce(&mut Vid) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match self.verified_vids.write()?.get_mut(vid) {
            Some(resolved) => change(resolved),
            None => Err(Error::UnverifiedVid(vid.to_string())),
        }
    }

    /// Retrieve the [PrivateVid] identified by `vid` from the database, if it exists.
    pub(crate) fn get_private_vid(&self, vid: &str) -> Result<PrivateVid, Error> {
        match self.private_vids.read()?.get(vid) {
            Some(resolved) => Ok(resolved.clone()),
            None => Err(Error::UnverifiedVid(vid.to_string())),
        }
    }

    /// Retrieve the [Vid] identified by `vid` from the database, if it exists.
    pub(crate) fn get_verified_vid(&self, vid: &str) -> Result<Vid, Error> {
        match self.verified_vids.read()?.get(vid) {
            Some(resolved) => Ok(resolved.clone()),
            None => Err(Error::UnverifiedVid(vid.to_string())),
        }
    }

    /// Decode an encrypted `message``, which has to be addressed to one of the VID's in `receivers`, and has to have
    /// `verified_vids` as one of the senders.
    pub(crate) fn decode_message(
        self,
        message: &mut [u8],
    ) -> Result<ReceivedTspMessage<Vid>, Error> {
        let probed_message = tsp_cesr::probe(message)?;

        match probed_message {
            EnvelopeType::EncryptedMessage {
                sender,
                receiver: intended_receiver,
            } => {
                let intended_receiver = std::str::from_utf8(intended_receiver)?;

                let Ok(intended_receiver) = self.get_private_vid(intended_receiver) else {
                    return Err(CryptoError::UnexpectedRecipient.into());
                };

                let sender = std::str::from_utf8(sender)?;

                let Ok(sender) = self.get_verified_vid(sender) else {
                    return Err(Error::UnverifiedVid(sender.to_string()));
                };

                let (nonconfidential_data, payload, raw_bytes) =
                    tsp_crypto::open(&intended_receiver, &sender, message)?;

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
                        self.decode_message(&mut inner)
                    }
                    Payload::RoutedMessage(hops, message) => {
                        let next_hop = std::str::from_utf8(hops[0])?;

                        let Ok(next_hop) = self.get_verified_vid(next_hop) else {
                            return Err(Error::UnverifiedVid(next_hop.to_string()));
                        };

                        Ok(ReceivedTspMessage::ForwardRequest {
                            sender,
                            next_hop,
                            route: hops[1..].iter().map(|x| x.to_vec()).collect(),
                            opaque_payload: message.to_owned(),
                        })
                    }
                    Payload::RequestRelationship => Ok(ReceivedTspMessage::RequestRelationship {
                        sender,
                        thread_id: tsp_crypto::sha256(raw_bytes),
                    }),
                    Payload::AcceptRelationship { thread_id } => {
                        let mut status = self.relation_status.write()?;
                        let Some(relation) = status.get_mut(sender.identifier()) else {
                            //TODO: should we inform the user of who sent this?
                            return Err(Error::Relationship(
                                "received confirmation of a relation with an unknown entity".into(),
                            ));
                        };

                        let RelationshipStatus::Unidirectional(digest) = relation else {
                            return Err(Error::Relationship(
                                "received confirmation of a relation that we did not want".into(),
                            ));
                        };

                        if thread_id != *digest {
                            return Err(Error::Relationship(
                                "attempt to change the terms of the relationship".into(),
                            ));
                        }

                        *relation = RelationshipStatus::Bidirectional(*digest);

                        Ok(ReceivedTspMessage::AcceptRelationship { sender })
                    }
                    Payload::CancelRelationship { thread_id } => {
                        let mut status = self.relation_status.write()?;
                        if let Some(relation) = status.get_mut(sender.identifier()) {
                            match relation {
                                RelationshipStatus::Bidirectional(digest)
                                | RelationshipStatus::Unidirectional(digest) => {
                                    if thread_id != *digest {
                                        return Err(Error::Relationship(
                                            "invalid attempt to end the relationship".into(),
                                        ));
                                    }
                                    *relation = RelationshipStatus::Unrelated;
                                }
                                _ => todo!(),
                            }
                        }

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

                    if !self.has_private_vid(intended_receiver)? {
                        return Err(CryptoError::UnexpectedRecipient.into());
                    }
                };

                let sender = std::str::from_utf8(sender)?;

                let Ok(sender) = self.get_verified_vid(sender) else {
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
}
