use async_stream::stream;
use futures_util::StreamExt;
use tokio_util::bytes::BytesMut;
use url::Url;

use tsp_definitions::Error;

use crate::TSPStream;

pub(crate) const SCHEME_HTTP: &str = "http";
pub(crate) const SCHEME_HTTPS: &str = "https";

pub(crate) const SCHEME_WS: &str = "ws";
pub(crate) const SCHEME_WSS: &str = "wss";

pub(crate) async fn send_message(tsp_message: &[u8], url: &Url) -> Result<(), Error> {
    let client = reqwest::Client::new();

    client
        .post(url.clone())
        .body(tsp_message.to_vec())
        .send()
        .await?;

    Ok(())
}

pub(crate) async fn receive_messages(address: &Url) -> Result<TSPStream, Error> {
    let mut ws_address = address.clone();

    match address.scheme() {
        SCHEME_HTTP => ws_address.set_scheme(SCHEME_WS),
        SCHEME_HTTPS => ws_address.set_scheme(SCHEME_WSS),
        _ => Err(()),
    }
    .map_err(|_| Error::InvalidTransportScheme)?;

    let ws_stream = match tokio_tungstenite::connect_async(ws_address).await {
        Ok((stream, _)) => stream,
        Err(e) => {
            dbg!(e);

            return Err(Error::InvalidTransportScheme);
        }
    };

    let (_, mut receiver) = ws_stream.split();

    Ok(Box::pin(stream! {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                tokio_tungstenite::tungstenite::Message::Binary(b) => {
                    yield Ok(BytesMut::from(&b[..]));
                }
                _ => {
                    yield Err(Error::UnexpectedControlMessage);
                }
            };
        }
    }))
}
