use futures::Stream;
use tokio_util::bytes::BytesMut;
use tsp_definitions::Error;
use url::Url;

pub mod tcp;

pub async fn send_message(transport: &Url, tsp_message: &[u8]) -> Result<(), Error> {
    match transport.scheme() {
        tcp::SCHEME => tcp::send_message(tsp_message, transport).await,
        _ => Err(Error::InvalidTransportScheme),
    }
}

pub async fn receive_messages(
    transport: &Url,
) -> Result<impl Stream<Item = Result<BytesMut, Error>>, Error> {
    match transport.scheme() {
        tcp::SCHEME => tcp::receive_messages(transport).await,
        _ => Err(Error::InvalidTransportScheme),
    }
}
