use tsp_definitions::Error;
use url::Url;

pub mod tcp;

pub async fn send_message(transport: &Url, tsp_message: &[u8]) -> Result<(), Error> {
    match transport.scheme() {
        tcp::SCHEME => tcp::send_message(tsp_message, transport).await,
        _ => Err(Error::InvalidTransportScheme),
    }
}
