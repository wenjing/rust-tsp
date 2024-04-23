#[derive(thiserror::Error, Debug)]
pub enum VidError {
    #[error("fetching '{0}' failed: {1}")]
    Http(String, reqwest::Error),
    #[error("deserializing '{0}' failed: {1}")]
    Json(String, reqwest::Error),
    #[error("connection to '{0}' failed: {1}")]
    Connection(String, std::io::Error),
    #[error("invalid VID '{0}'")]
    InvalidVid(String),
    #[error("could not resolve VID '{0}'")]
    ResolveVid(&'static str),
}
