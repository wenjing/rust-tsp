use crate::Error;
use aries_askar::StoreKeyMethod;

#[allow(dead_code)]
struct Vault {
    inner: aries_askar::Store,
}

#[allow(dead_code)]
impl Vault {
    pub async fn new_sqlite(name: &str, password: &[u8]) -> Result<Self, Error> {
        let pass_key = aries_askar::Store::new_raw_key(Some(password)).unwrap();

        let inner = aries_askar::Store::provision(
            &format!("sqlite://{name}.sqlite"),
            StoreKeyMethod::RawKey,
            pass_key,
            None,
            true,
        )
        .await
        .unwrap();

        Ok(Self { inner })
    }

    pub async fn open_sqlite(name: &str, password: &[u8]) -> Result<Self, Error> {
        let pass_key = aries_askar::Store::new_raw_key(Some(password)).unwrap();

        let inner = aries_askar::Store::open(
            &format!("sqlite://{name}.sqlite"),
            Some(StoreKeyMethod::RawKey),
            pass_key,
            None,
        )
        .await
        .unwrap();

        Ok(Self { inner })
    }
}
