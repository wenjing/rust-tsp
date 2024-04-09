use async_stream::stream;
use futures_util::StreamExt;
use tokio_util::bytes::BytesMut;
use url::Url;

use tsp_definitions::Error;

use crate::TSPStream;

pub(crate) const SCHEME_HTTP: &str = "http";
pub(crate) const SCHEME_HTTPS: &str = "https";

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
    let mut stream = reqwest::get(address.clone()).await?.bytes_stream();

    Ok(Box::pin(stream! {
        while let Some(item) = stream.next().await {
            yield item
                .map(|b| BytesMut::from(&b[..]))
                .map_err(Error::from);
        }
    }))
}
