//! # Trust Spanning Protocol
//!
//! The Trust Spanning Protocol (TSP) is a protocol for secure communication
//! between entities identified by their Verified Identities (VID's).
//!
//! The primary API this crates exposes is the [AsyncStore] struct, which
//! is used to manage and resolve VID's, as well as send and receive messages
//! between them.
//!
//! # Example
//!
//! The following example demonstrates how to send a message from Alice to Bob
//!
//! ```no_run
//! use tsp::{AsyncStore, OwnedVid, Error, ReceivedTspMessage};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Error> {
//!     // bob database
//!     let mut bob_db = AsyncStore::new();
//!     let bob_vid = OwnedVid::from_file("../examples/test/bob.json").await?;
//!     bob_db.add_private_vid(bob_vid)?;
//!     bob_db.verify_vid("did:web:did.tsp-test.org:user:alice").await?;
//!
//!     let mut bobs_messages = bob_db.receive("did:web:did.tsp-test.org:user:bob").await?;
//!
//!     // alice database
//!     let mut alice_db = AsyncStore::new();
//!     let alice_vid = OwnedVid::from_file("../examples/test/bob.json").await?;
//!     alice_db.add_private_vid(alice_vid)?;
//!     alice_db.verify_vid("did:web:did.tsp-test.org:user:bob").await?;
//!
//!     // send a message
//!     alice_db.send(
//!         "did:web:did.tsp-test.org:user:alice",
//!         "did:web:did.tsp-test.org:user:bob",
//!         Some(b"extra non-confidential data"),
//!         b"hello world",
//!     ).await?;
//!
//!     // receive a message
//!     let Some(Ok(ReceivedTspMessage::GenericMessage { message, .. }))=
//!         bobs_messages.recv().await else {
//!         panic!("bob did not receive a generic message")
//!     };
//!
//!     assert_eq!(message, b"hello world");
//!
//!     Ok(())
//! }
//! ```
//!
pub mod cesr;
pub mod crypto;
pub mod definitions;
pub mod vid;

#[cfg(feature = "async")]
pub mod transport;

#[cfg(feature = "async")]
mod async_store;

mod error;
mod store;

#[cfg(feature = "async")]
#[cfg(test)]
mod test;

pub use crate::{
    definitions::{Payload, PrivateVid, ReceivedTspMessage, VerifiedVid},
    vid::{OwnedVid, Vid},
};

#[cfg(feature = "async")]
pub use async_store::AsyncStore;

pub use error::Error;
pub use store::{ExportVid, Store};
