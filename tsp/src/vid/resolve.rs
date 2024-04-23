use super::{
    did::{self, peer},
    error::VidError,
};
use crate::Vid;

pub async fn verify_vid(id: &str) -> Result<Vid, VidError> {
    let parts = id.split(':').collect::<Vec<&str>>();

    match parts.get(0..2) {
        Some([did::SCHEME, did::web::SCHEME]) => {
            let url = did::web::resolve_url(&parts)?;

            let response = reqwest::get(url.as_ref())
                .await
                .map_err(|e| VidError::Http(url.to_string(), e))?;

            let did_document = match response.error_for_status() {
                Ok(r) => r
                    .json::<did::web::DidDocument>()
                    .await
                    .map_err(|e| VidError::Json(url.to_string(), e))?,
                Err(e) => Err(VidError::Http(url.to_string(), e))?,
            };

            did::web::resolve_document(did_document, id)
        }
        Some([did::SCHEME, did::peer::SCHEME]) => peer::verify_did_peer(&parts),
        _ => Err(VidError::InvalidVid(id.to_string())),
    }
}
