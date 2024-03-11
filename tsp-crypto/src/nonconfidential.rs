use tsp_definitions::{Error, NonConfidentialData, Sender, TSPMessage, VerifiedVid};

/// Construct and sign a non-confidential TSP message
pub fn sign(
    _sender: &dyn Sender,
    _nonconfidential_data: NonConfidentialData,
) -> Result<TSPMessage, Error> {
    unimplemented!();
}

/// Decode a CESR Authentic Non-Confidential Message, verify the signature and return its contents
pub fn verify<'a>(
    _sender: &dyn VerifiedVid,
    _tsp_message: &'a mut [u8],
) -> Result<NonConfidentialData<'a>, Error> {
    unimplemented!();
}
