use futures::{Stream, StreamExt};
use tsp_definitions::{Digest, Error, Payload, ReceivedTspMessage, Receiver, Sender, VerifiedVid};
use tsp_vid::Vid;

mod vid_database;

pub use vid_database::VidDatabase;

/// Resolved a VID given the VID as a string
///
/// # Arguments
///
/// * `vid` - A VID, for example `did:web:did.tsp-test.org:user:bob`
///
/// # Example
///
/// ```
/// #[tokio::main]
/// async fn main() {
///     use tsp_definitions::VerifiedVid;
///
///     let relation = tsp::resolve_vid("did:web:did.tsp-test.org:user:bob").await.unwrap();
///
///     assert_eq!(relation.endpoint().as_str(), "tcp://127.0.0.1:1337");
/// }
/// ```
pub async fn resolve_vid(vid: &str) -> Result<Vid, Error> {
    tsp_vid::resolve::resolve_vid(vid).await
}

/// Send data to a resolved VID using the TSP
/// Encodes, encrypts, signs and sends a TSP message
///
/// # Arguments
///
/// * `sender`               - A sender identity implementing the trait `Sender`
/// * `receiver`             - A receiver identity implementing the trait `ResolvedVid`
/// * `nonconfidential_data` - Optional extra non-confidential data
/// * `payload`              - The raw message payload as byte slice
///
/// # Example
///
/// ```
/// #[tokio::main]
/// async fn main() {
///     use tsp_vid::PrivateVid;
///
///     let sender = PrivateVid::from_file("../examples/test/alice.json").await.unwrap();
///     let receiver = tsp::resolve_vid("did:web:did.tsp-test.org:user:bob").await.unwrap();
///
///     let result = tsp::send(&sender, &receiver, None, b"hello world").await;
/// }
/// ```
pub async fn send(
    sender: &impl Sender,
    receiver: &impl VerifiedVid,
    nonconfidential_data: Option<&[u8]>,
    message: &[u8],
) -> Result<(), Error> {
    let tsp_message = tsp_crypto::seal(
        sender,
        receiver,
        nonconfidential_data,
        Payload::Content(message),
    )?;
    tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

    Ok(())
}

/// Listen for incopming TSP messages, given the transport provided by the receiver VID
///
/// # Arguments
///
/// * `receiver`  - A receiver identity implementing the trait `Receiver`
/// * `listening` - Optional signal receiver, notified when the receiver is ready to accept incoming messages
///
/// # Example
///
/// ```
/// #[tokio::main]
/// async fn main() {
///     use tsp_vid::PrivateVid;
///     use futures::StreamExt;
///
///     let receiver = PrivateVid::from_file("../examples/test/bob.json").await.unwrap();
///
///     let messages = tsp::receive(&receiver, None).unwrap();
///     tokio::pin!(messages);
///
///     while let Some(Ok(msg)) = messages.next().await {
///         println!("Received {:?}", msg);
///     }
/// }
/// ```
pub fn receive(
    receiver: &impl Receiver,
    listening: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<impl Stream<Item = Result<ReceivedTspMessage<Vid>, Error>> + '_, Error> {
    let messages = tsp_transport::receive_messages(receiver.endpoint())?;

    listening.map(|s| s.send(()));

    Ok(messages.then(|data| async {
        let mut message = data?;

        let (sender, intended_receiver) = tsp_cesr::get_sender_receiver(&mut message)?;

        if intended_receiver != receiver.identifier() {
            return Err(Error::UnexpectedRecipient);
        }

        let sender = resolve_vid(std::str::from_utf8(sender)?).await?;
        let (nonconfidential_data, payload, raw_bytes) =
            tsp_crypto::open(receiver, &sender, &mut message)?;

        Ok(match payload {
            Payload::Content(message) => ReceivedTspMessage::GenericMessage {
                sender,
                nonconfidential_data: nonconfidential_data.map(|v| v.to_vec()),
                message: message.to_owned(),
            },
            Payload::RequestRelationship => ReceivedTspMessage::RequestRelationship {
                sender,
                thread_id: tsp_crypto::sha256(raw_bytes),
            },
            // TODO: check the digest and record that we have this relationship
            Payload::AcceptRelationship { thread_id: _digest } => {
                //TODO: if the thread_id is invalid, don't send this response
                ReceivedTspMessage::AcceptRelationship { sender }
            }
            // TODO: record that we have to end this relationship
            Payload::CancelRelationship => ReceivedTspMessage::CancelRelationship { sender },
        })
    }))
}

/// Request a direct relationship with a resolved VID using the TSP
/// Encodes the control message, encrypts, signs and sends a TSP message
///
/// # Arguments
///
/// * `sender`               - A sender identity implementing the trait `Sender`
/// * `receiver`             - A receiver identity implementing the trait `ResolvedVid`
///
/// # Example
///
/// ```
/// #[tokio::main]
/// async fn main() {
///     use tsp_vid::PrivateVid;
///
///     let sender = PrivateVid::from_file("../examples/test/alice.json").await.unwrap();
///     let receiver = tsp::resolve_vid("did:web:did.tsp-test.org:user:bob").await.unwrap();
///
///     let result = tsp::send_relationship_request(&sender, &receiver).await;
/// }
/// ```
pub async fn send_relationship_request(
    sender: &impl Sender,
    receiver: &impl VerifiedVid,
) -> Result<(), Error> {
    let tsp_message = tsp_crypto::seal(sender, receiver, None, Payload::RequestRelationship)?;
    tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

    //TODO: record the thread-id of the message we sent
    Ok(())
}

/// Accept a direct relationship with a resolved VID using the TSP
/// Encodes the control message, encrypts, signs and sends a TSP message
///
/// # Arguments
///
/// * `sender`               - A sender identity implementing the trait `Sender`
/// * `receiver`             - A receiver identity implementing the trait `ResolvedVid`
/// * `thread_id`            - The thread id that was contained in the relationship request
///
/// # Example
///
/// ```
/// #[tokio::main]
/// async fn main() {
///     use futures::StreamExt;
///     use tsp_vid::PrivateVid;
///     use tsp_definitions::ReceivedTspMessage;
///
///     let owner = PrivateVid::from_file("../examples/test/alice.json").await.unwrap();
///
///     let messages = tsp::receive(&owner, None).unwrap();
///     tokio::pin!(messages);
///
///     while let Some(Ok(msg)) = messages.next().await {
///         if let ReceivedTspMessage::RequestRelationship { sender: other, thread_id } = msg {
///             let result = tsp::send_relationship_accept(&owner, &other, thread_id).await;
///         }
///     }
/// }
/// ```
pub async fn send_relationship_accept(
    sender: &impl Sender,
    receiver: &impl VerifiedVid,
    thread_id: Digest,
) -> Result<(), Error> {
    let tsp_message = tsp_crypto::seal(
        sender,
        receiver,
        None,
        Payload::AcceptRelationship { thread_id },
    )?;
    tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

    Ok(())
}

/// Cancels a direct relationship with a resolved VID using the TSP
/// Encodes the control message, encrypts, signs and sends a TSP message
///
/// # Arguments
///
/// * `sender`               - A sender identity implementing the trait `Sender`
/// * `receiver`             - A receiver identity implementing the trait `ResolvedVid`
///
/// # Example
///
/// ```
/// #[tokio::main]
/// async fn main() {
///     use tsp_vid::PrivateVid;
///
///     let sender = PrivateVid::from_file("../examples/test/alice.json").await.unwrap();
///     let receiver = tsp::resolve_vid("did:web:did.tsp-test.org:user:bob").await.unwrap();
///
///     let result = tsp::send_relationship_cancel(&sender, &receiver).await;
/// }
/// ```
pub async fn send_relationship_cancel(
    sender: &impl Sender,
    receiver: &impl VerifiedVid,
) -> Result<(), Error> {
    let tsp_message = tsp_crypto::seal(sender, receiver, None, Payload::CancelRelationship)?;
    tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::{receive, resolve_vid, send};
    use futures::StreamExt;
    use tokio::sync::oneshot;
    use tsp_transport::tcp::start_broadcast_server;

    #[tokio::test]
    #[serial_test::serial(tcp)]
    async fn highlevel() {
        let alice = tsp_vid::PrivateVid::from_file("../examples/test/alice.json")
            .await
            .unwrap();

        let bob = resolve_vid("did:web:did.tsp-test.org:user:bob")
            .await
            .unwrap();

        let payload = b"hello world";

        start_broadcast_server("127.0.0.1:1337").await.unwrap();

        let (receiver_tx, receiver_rx) = oneshot::channel::<()>();
        let handle = tokio::task::spawn(async {
            let bob_receiver = tsp_vid::PrivateVid::from_file("../examples/test/bob.json")
                .await
                .unwrap();

            let stream = receive(&bob_receiver, Some(receiver_tx)).unwrap();
            tokio::pin!(stream);

            let tsp_definitions::ReceivedTspMessage::GenericMessage { message, .. } =
                stream.next().await.unwrap().unwrap()
            else {
                panic!()
            };

            assert_eq!(message, b"hello world");
        });

        receiver_rx.await.unwrap();

        send(&alice, &bob, None, payload).await.unwrap();

        handle.await.unwrap();
    }
}
