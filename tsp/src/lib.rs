use futures::{Stream, StreamExt};
use tsp_definitions::{Error, ReceivedTspMessage, Receiver, ResolvedVid, Sender};
use tsp_vid::Vid;

pub async fn resolve_vid(vid: &str) -> Result<Vid, Error> {
    tsp_vid::resolve::resolve_vid(vid).await
}

pub async fn send(
    sender: &impl Sender,
    receiver: &impl ResolvedVid,
    nonconfidential_data: Option<&[u8]>,
    payload: &[u8],
) -> Result<(), Error> {
    let tsp_message = tsp_crypto::seal(sender, receiver, nonconfidential_data, payload)?;
    tsp_transport::send_message(receiver.endpoint(), &tsp_message).await?;

    Ok(())
}

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

        let sender = resolve_vid(std::str::from_utf8(sender).unwrap()).await?;
        let (nonconfidential_data, payload) = tsp_crypto::open(receiver, &sender, &mut message)?;

        Ok(ReceivedTspMessage::<Vid> {
            sender,
            nonconfidential_data: nonconfidential_data.map(|v| v.to_vec()),
            payload: payload.to_owned(),
        })
    }))
}

#[cfg(test)]
mod test {
    use crate::{receive, resolve_vid, send};
    use futures::StreamExt;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn highlevel() {
        let address = "127.0.0.1:1337";
        let alice = tsp_vid::VidController::from_file("../examples/test/alice.identity")
            .await
            .unwrap();
        let bob = resolve_vid("did:web:did.tweede.golf:user:bob")
            .await
            .unwrap();
        let payload = b"hello world";
        let (tx, rx) = oneshot::channel();

        tokio::task::spawn(async move {
            tsp_transport::tcp::broadcast_server(address, Some(tx))
                .await
                .unwrap();
        });

        rx.await.unwrap();

        let (receiver_tx, receiver_rx) = oneshot::channel::<()>();
        let handle = tokio::task::spawn(async {
            let bob_receiver = tsp_vid::VidController::from_file("../examples/test/bob.identity")
                .await
                .unwrap();

            let stream = receive(&bob_receiver, Some(receiver_tx)).unwrap();
            tokio::pin!(stream);

            let message = stream.next().await.unwrap().unwrap();

            assert_eq!(message.payload, b"hello world");
        });

        receiver_rx.await.unwrap();

        send(&alice, &bob, None, payload).await.unwrap();

        handle.await.unwrap();
    }
}
