use tsp_definitions::TSPStream;
use url::Url;

use crate::error::Error;

pub mod error;
mod http;
pub mod tcp;

pub async fn send_message(transport: &Url, tsp_message: &[u8]) -> Result<(), Error> {
    match transport.scheme() {
        tcp::SCHEME => tcp::send_message(tsp_message, transport).await,
        http::SCHEME_HTTP => http::send_message(tsp_message, transport).await,
        http::SCHEME_HTTPS => http::send_message(tsp_message, transport).await,
        _ => Err(Error::InvalidTransportScheme(
            transport.scheme().to_string(),
        )),
    }
}

pub async fn receive_messages(transport: &Url) -> Result<TSPStream<Error>, Error> {
    match transport.scheme() {
        tcp::SCHEME => tcp::receive_messages(transport).await,
        http::SCHEME_HTTP => http::receive_messages(transport).await,
        http::SCHEME_HTTPS => http::receive_messages(transport).await,
        _ => Err(Error::InvalidTransportScheme(
            transport.scheme().to_string(),
        )),
    }
}
