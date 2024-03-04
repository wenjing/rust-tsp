use tsp_definitions::Error;

use crate::Vid;

mod did;

pub async fn resolve_vid<Identifier: ToString>(id: Identifier) -> Result<Vid<Identifier>, Error> {
    let id_string = id.to_string();
    let parts = id_string.split(':').collect::<Vec<&str>>();

    match parts.get(0..2) {
        Some([did::SCHEME, did::web::SCHEME]) => {
            let url = did::web::resolve_url(&parts)?;
            let did_document = reqwest::get(url)
                .await?
                .json::<did::web::DidDocument>()
                .await?;

            did::web::resolve_document(did_document, id)
        }
        _ => Err(Error::UnknownVIDType),
    }
}
