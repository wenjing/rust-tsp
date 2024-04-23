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
//! use tsp::{AsyncStore, PrivateVid, Error, ReceivedTspMessage};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Error> {
//!     // bob database
//!     let mut bob_db = AsyncStore::new();
//!     bob_db.add_private_vid_from_file("test/bob.json").await?;
//!     bob_db.verify_vid("did:web:did.tsp-test.org:user:alice").await?;
//!
//!     let mut bobs_messages = bob_db.receive("did:web:did.tsp-test.org:user:bob").await?;
//!
//!     // alice database
//!     let mut alice_db = AsyncStore::new();
//!     alice_db.add_private_vid_from_file("test/alice.json").await?;
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
use tsp_definitions::Digest;

mod async_store;
mod error;
mod store;

#[cfg(test)]
mod test;

pub use async_store::AsyncStore;
pub use error::Error;
pub use store::Store;
pub use tsp_definitions::{Payload, ReceivedTspMessage, VerifiedVid};
pub use tsp_vid::{PrivateVid, Vid};

#[derive(Clone, Copy, Debug)]
pub(crate) enum RelationshipStatus {
    _Controlled,
    Bidirectional(Digest),
    Unidirectional(Digest),
    Unrelated,
}
