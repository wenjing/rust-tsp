#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("fetching '{0}': {1}")]
    Http(String, reqwest::Error),
    #[error("deserializing '{0}': {1}")]
    Json(String, reqwest::Error),
    #[error("connection error '{0}': {1}")]
    Connection(String, std::io::Error),
    #[error("invalid VID: {0}")]
    InvalidVid(String),
    #[error("resolve VID: {0}")]
    ResolveVid(&'static str),
}
