use async_stream::stream;
use futures_util::StreamExt;
use tokio_util::bytes::BytesMut;
use tsp_definitions::TSPStream;
use url::Url;

use crate::Error;

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
        .await
        .map_err(|e| Error::Http(url.to_string(), e))?;

    Ok(())
}

pub(crate) async fn receive_messages(address: &Url) -> Result<TSPStream<Error>, Error> {
    let mut ws_address = address.clone();

    match address.scheme() {
        SCHEME_HTTP => ws_address.set_scheme(SCHEME_WS),
        SCHEME_HTTPS => ws_address.set_scheme(SCHEME_WSS),
        _ => Err(()),
    }
    .map_err(|_| Error::InvalidTransportScheme(address.scheme().to_owned()))?;

    let ws_stream = match tokio_tungstenite::connect_async(&ws_address).await {
        Ok((stream, _)) => stream,
        Err(e) => return Err(Error::Websocket(ws_address.to_string(), e)),
    };

    let (_, mut receiver) = ws_stream.split();

    Ok(Box::pin(stream! {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                tokio_tungstenite::tungstenite::Message::Binary(b) => {
                    yield Ok(BytesMut::from(&b[..]));
                }
                m => {
                    yield Err(Error::InvalidMessageReceived(
                        m
                            .into_text()
                            .map_err(|_| Error::InvalidMessageReceived("invalid UTF8 character encountered".to_string()))?
                    ));
                }
            };
        }
    }))
}
