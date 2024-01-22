use base64ct::{Base64Unpadded as B64, Encoding};
use rand::{rngs::StdRng, SeedableRng};

use hpke::{
    aead::ChaCha20Poly1305 as Aead, kdf::HkdfSha256 as Kdf, kem::X25519HkdfSha256 as KemType,
    Deserializable, Kem, Serializable,
};

use crate::api::{Error, Identifier};

type Signature = [u8; 48];

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "SerdeRepresentation"))]
#[cfg_attr(feature = "serde", serde(into = "SerdeRepresentation"))]
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Vid {
    ident: url::Url,
    public: <KemType as Kem>::PublicKey,
    // note: we only need to carry the signature for the 'display' method; as soon as an object of
    // this type is constructed we have a guarantee that this signature has been checked.
    signature: Signature,
}

const INFO: &[u8] = b"TG Autonomous Self Signed ID";

impl Identifier<KemType> for Vid {
    fn endpoint(&self) -> &url::Url {
        &self.ident
    }

    fn public_key(&self) -> &<KemType as Kem>::PublicKey {
        &self.public
    }

    fn parse(display_string: &str) -> Result<Vid, Error> {
        let mut public_bytes: [u8; 32] = [0; 32];
        let mut signature: [u8; 48] = [0; 48];

        let mut chars = display_string.chars();

        B64::decode(
            chars
                .by_ref()
                .take(B64::encoded_len(&public_bytes))
                .collect::<String>(),
            &mut public_bytes,
        )?;

        B64::decode(
            chars
                .by_ref()
                .skip_while(|&c| c == '=')
                .take(B64::encoded_len(&signature))
                .collect::<String>(),
            &mut signature,
        )?;

        let ident = url::Url::parse(&chars.skip_while(|&c| c == '=').collect::<String>())?;

        let public = <KemType as Kem>::PublicKey::from_bytes(&public_bytes)?;

        Self::make(ident, public, signature)
    }

    fn display(&self) -> ascii::AsciiString {
        let ident = &self.ident;
        let public = B64::encode_string(&self.public.to_bytes());
        let signature = B64::encode_string(&self.signature);

        use std::str::FromStr;
        ascii::AsciiString::from_str(&format!("{public}{signature}{ident}"))
            .expect("URL encoding contained non-ASCII characters")
    }
}

impl Vid {
    pub fn make(
        ident: url::Url,
        public: <KemType as Kem>::PublicKey,
        signature: Signature,
    ) -> Result<Vid, Error> {
        #[allow(non_snake_case)]
        let GLOBAL_PRIVATE_KEY: <KemType as Kem>::PrivateKey =
            <KemType as Kem>::PrivateKey::from_bytes(&[0; 32]).unwrap();

        let mut verifier = hpke::setup_receiver::<Aead, Kdf, KemType>(
            &hpke::OpModeR::Auth(public.clone()),
            &GLOBAL_PRIVATE_KEY,
            &<KemType as Kem>::EncappedKey::from_bytes(&signature[..32])?,
            INFO,
        )?;

        verifier.open_in_place_detached(
            &mut [],
            ident.as_str().as_bytes(),
            &hpke::aead::AeadTag::from_bytes(&signature[32..])?,
        )?;

        Ok(Vid {
            ident,
            public,
            signature,
        })
    }

    pub fn new<Text: TryInto<url::Url>>(
        url: Text,
    ) -> Result<(Vid, <KemType as Kem>::PrivateKey), Text::Error> {
        let (sk, pk) = KemType::gen_keypair(&mut StdRng::from_entropy());

        Ok((Vid::generate_from_keypair(url.try_into()?, &sk, pk), sk))
    }

    pub fn generate_from_keypair(
        ident: url::Url,
        secret: &<KemType as Kem>::PrivateKey,
        public: <KemType as Kem>::PublicKey,
    ) -> Vid {
        #[allow(non_snake_case)]
        let GLOBAL_PRIVATE_KEY: <KemType as Kem>::PrivateKey =
            <KemType as Kem>::PrivateKey::from_bytes(&[0; 32]).unwrap();
        #[allow(non_snake_case)]
        let GLOBAL_PUBLIC_KEY: <KemType as Kem>::PublicKey =
            <KemType as Kem>::sk_to_pk(&GLOBAL_PRIVATE_KEY);

        let (encap_key, mut signer) = hpke::setup_sender::<Aead, Kdf, KemType, _>(
            &hpke::OpModeS::Auth((secret.clone(), public.clone())),
            &GLOBAL_PUBLIC_KEY,
            INFO,
            &mut StdRng::from_entropy(),
        )
        .expect("Invalid public key");

        let mac: [u8; 16] = signer
            .seal_in_place_detached(&mut [], ident.as_str().as_bytes())
            .expect("Signature generation failed")
            .to_bytes()
            .into();

        let encap_key: [u8; 32] = encap_key.to_bytes().into();

        let signature: [u8; 48] =
            std::array::from_fn(|i| if i < 32 { encap_key[i] } else { mac[i - 32] });

        Vid {
            public,
            signature,
            ident,
        }
    }
}

#[cfg(feature = "serde")]
type SerdeRepresentation = (Vec<u8>, <KemType as Kem>::PublicKey, url::Url);

#[cfg(feature = "serde")]
impl TryFrom<SerdeRepresentation> for Vid {
    type Error = Error;
    fn try_from(data: SerdeRepresentation) -> Result<Vid, Error> {
        Vid::make(
            data.2,
            data.1,
            data.0.try_into().expect("Array length invalid"),
        )
    }
}

#[cfg(feature = "serde")]
impl From<Vid> for SerdeRepresentation {
    fn from(data: Vid) -> SerdeRepresentation {
        (data.signature.to_vec(), data.public, data.ident)
    }
}

#[cfg(test)]
mod test {
    use super::{Error, Identifier, Vid};

    #[test]
    fn base64_error() {
        let vid = "CJ15Zb!V3qE7XJHvlVmaI00plPtdbEgmU6RE9isW9HclSFefCdxx3uccHZnamFltxxkUEVG8p0O3HhIqcKIZVCjX0V7FrnO6C1ncE0IfYqdmailto:tsp@tweedegolf.com";
        assert!(matches!(Vid::parse(vid).unwrap_err(), Error::Encoding(_)));
    }

    #[test]
    fn url_error() {
        let vid = "CJ15Zb6V3qE7XJHvlVmaI00plPtdbEgmU6RE9isW9HclSFefCdxx3uccHZnamFltxxkUEVG8p0O3HhIqcKIZVCjX0V7FrnO6C1ncE0IfYqdmailtotsptweedegolf.com";
        assert!(matches!(Vid::parse(vid).unwrap_err(), Error::Transport(_)));
    }

    #[test]
    fn crypto_error() {
        let vid = "CJ15Zb6V3qE7XJHvlVmaI00plPtdbEgmU6RE9isW9HclSFefCdxx3uccHZnamFltxxkUEVG8p0O3HhIqcKIZVCjX0V7FrnO6C1ncE0IfYqdmailto:tsp@tweedegalf.com";
        assert!(matches!(
            Vid::parse(vid).unwrap_err(),
            Error::VerificationFailed(_)
        ));
    }

    #[test]
    fn okay() {
        fn check_vid(vid: impl AsRef<str>, text: &str) {
            let vid = Vid::parse(vid.as_ref()).unwrap();
            assert_eq!(
                vid.endpoint(),
                &TryInto::<url::Url>::try_into(text).unwrap()
            );
            //vid.public_key()
            //    .verify(text.as_bytes(), &vid.signature)
            //    .unwrap();
        }

        let vid1 = "CJ15Zb6V3qE7XJHvlVmaI00plPtdbEgmU6RE9isW9HclSFefCdxx3uccHZnamFltxxkUEVG8p0O3HhIqcKIZVCjX0V7FrnO6C1ncE0IfYqdmailto:tsp@tweedegolf.com";
        let vid2 = &Vid::new("mailto:tsp@tweedegolf.com").unwrap().0.display();
        check_vid(vid1, "mailto:tsp@tweedegolf.com");
        check_vid(vid2, "mailto:tsp@tweedegolf.com");
        assert_ne!(vid1, vid2);
    }
}
