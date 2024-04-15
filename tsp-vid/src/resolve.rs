use crate::{error::Error, Vid};

pub mod did;

pub async fn resolve_vid(id: &str) -> Result<Vid, Error> {
    let parts = id.split(':').collect::<Vec<&str>>();

    match parts.get(0..2) {
        Some([did::SCHEME, did::web::SCHEME]) => {
            let url = did::web::resolve_url(&parts)?;

            let did_document = reqwest::get(url.as_ref())
                .await
                .map_err(|e| Error::Http(url.to_string(), e))?
                .json::<did::web::DidDocument>()
                .await
                .map_err(|e| Error::Json(url.to_string(), e))?;

            did::web::resolve_document(did_document, id)
        }
        Some([did::SCHEME, did::peer::SCHEME]) => did::peer::resolve_did_peer(&parts),
        _ => Err(Error::InvalidVid(id.to_string())),
    }
}
