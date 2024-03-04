use tsp_definitions::{Error, ResolvedVid, Sender};

pub async fn resolve_vid(vid: &str) -> Result<impl ResolvedVid, Error> {
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

// pub fn receive<V: ResolvedVid>(receiver: &impl Receiver) -> impl Stream<Item = ReceivedTspMessage<V>> {
// }

#[cfg(test)]
mod test {
    use crate::{resolve_vid, send};
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

        send(&alice, &bob, None, payload).await.unwrap();
    }
}
