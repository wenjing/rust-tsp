/// An error type to indicate something went wrong with encoding
#[derive(Clone, Copy, Debug)]
pub enum EncodeError {
    PayloadTooLarge,
}

/// An error type to indicate something went wrong with decoding
#[derive(Clone, Copy, Debug)]
pub enum DecodeError {
    UnexpectedData,
    UnexpectedMsgType,
    TrailingGarbage,
    SignatureError,
    VidError,
    VersionMismatch,
    MissingHops,
}

#[cfg(feature = "std")]
impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "std")]
impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncodeError {}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}
