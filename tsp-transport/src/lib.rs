use std::pin::Pin;

use futures::Stream;
use tokio_util::bytes::BytesMut;
use tsp_definitions::Error;
use url::Url;

mod http;
pub mod tcp;

pub async fn send_message(transport: &Url, tsp_message: &[u8]) -> Result<(), Error> {
    match transport.scheme() {
        tcp::SCHEME => tcp::send_message(tsp_message, transport).await,
        http::SCHEME_HTTP => http::send_message(tsp_message, transport).await,
        http::SCHEME_HTTPS => http::send_message(tsp_message, transport).await,
        _ => Err(Error::InvalidTransportScheme),
    }
}

type TSPStream = Pin<Box<dyn Stream<Item = Result<BytesMut, Error>> + Send>>;

pub async fn receive_messages(transport: &Url) -> Result<TSPStream, Error> {
    match transport.scheme() {
        tcp::SCHEME => tcp::receive_messages(transport).await,
        http::SCHEME_HTTP => http::receive_messages(transport).await,
        http::SCHEME_HTTPS => http::receive_messages(transport).await,
        _ => Err(Error::InvalidTransportScheme),
    }
}
