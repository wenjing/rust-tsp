use futures::{Stream, StreamExt};
use tsp_definitions::{
    Error, MessageType, Payload, ReceivedTspMessage, Receiver, Sender, VerifiedVid,
};
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
///         println!("Received {:?}", msg.message);
///     }
/// }
/// ```
pub fn receive(
    receiver: &impl Receiver,
    listening: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<impl Stream<Item = Result<ReceivedTspMessage<Vec<u8>, Vid>, Error>> + '_, Error> {
    let messages = tsp_transport::receive_messages(receiver.endpoint())?;

    listening.map(|s| s.send(()));

    Ok(messages.then(|data| async {
        let mut message = data?;

        let (sender, intended_receiver) = tsp_cesr::get_sender_receiver(&mut message)?;

        if intended_receiver != Some(receiver.identifier().as_bytes()) {
            return Err(Error::UnexpectedRecipient);
        }

        let sender = resolve_vid(std::str::from_utf8(sender)?).await?;
        let (nonconfidential_data, payload) = tsp_crypto::open(receiver, &sender, &mut message)?;

        match payload {
            Payload::Content(message) => Ok(ReceivedTspMessage::<Vec<u8>, Vid> {
                sender,
                nonconfidential_data: nonconfidential_data.map(|v| v.to_vec()),
                message: Payload::Content(message.to_owned()),
                message_type: MessageType::SignedAndEncrypted,
            }),
            _ => unimplemented!("receiving control messages not supported yet"),
        }
    }))
}

#[cfg(test)]
mod test {
    use crate::{receive, resolve_vid, send};
    use futures::StreamExt;
    use tokio::sync::oneshot;
    use tsp_definitions::Payload;
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

        let payload: &[u8] = b"hello world";

        start_broadcast_server("127.0.0.1:1337").await.unwrap();

        let (receiver_tx, receiver_rx) = oneshot::channel::<()>();
        let handle = tokio::task::spawn(async {
            let bob_receiver = tsp_vid::PrivateVid::from_file("../examples/test/bob.json")
                .await
                .unwrap();

            let stream = receive(&bob_receiver, Some(receiver_tx)).unwrap();
            tokio::pin!(stream);

            let message = stream.next().await.unwrap().unwrap();

            assert_eq!(message.message, Payload::Content(payload.to_vec()));
        });

        receiver_rx.await.unwrap();

        send(&alice, &bob, None, payload).await.unwrap();

        handle.await.unwrap();
    }
}
