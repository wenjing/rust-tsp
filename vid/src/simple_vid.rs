use base64ct::{Base64Unpadded as B64, Encoding};
use ed25519_dalek::{self as Ed, pkcs8::EncodePublicKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;

use crate::api::{Error, Identifier};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(PartialEq, Eq, Debug)]
pub struct Vid {
    ident: url::Url,
    public: Ed::VerifyingKey,
    // note: we only need to carry the signature for the 'display' method; as soon as an object of
    // this type is constructed we have a guarantee that this signature has been checked.
    signature: Ed::Signature,
}

impl Identifier for Vid {
    fn endpoint(&self) -> &url::Url {
        &self.ident
    }

    fn public_key(&self) -> &(impl Verifier<Signature> + EncodePublicKey + AsRef<[u8]>) {
        &self.public
    }

    fn parse(display_string: &str) -> Result<Vid, Error> {
        let mut public_bytes: [u8; 32] = [0; 32];
        let mut sig_bytes: [u8; 64] = [0; 64];

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
                .take(B64::encoded_len(&sig_bytes))
                .collect::<String>(),
            &mut sig_bytes,
        )?;

        let ident = url::Url::parse(&chars.skip_while(|&c| c == '=').collect::<String>())?;

        let public = Ed::VerifyingKey::from_bytes(&public_bytes)?;
        let signature = Ed::Signature::from_bytes(&sig_bytes);

        Self::make(ident, public, signature)
    }

    fn display(&self) -> ascii::AsciiString {
        let ident = &self.ident;
        let public = B64::encode_string(self.public.as_bytes());
        let signature = B64::encode_string(&self.signature.to_bytes());

        use std::str::FromStr;
        ascii::AsciiString::from_str(&format!("{public}{signature}{ident}"))
            .expect("URL encoding contained non-ASCII characters")
    }
}

impl Vid {
    pub fn make(
        ident: url::Url,
        public: Ed::VerifyingKey,
        signature: Ed::Signature,
    ) -> Result<Vid, Error> {
        public.verify(ident.as_str().as_bytes(), &signature)?;

        Ok(Vid {
            ident,
            public,
            signature,
        })
    }

    pub fn generate_from_key(ident: url::Url, secret: &Ed::SigningKey) -> Vid {
        let public = secret.verifying_key();
        let signature = secret.sign(ident.as_str().as_bytes());

        Vid {
            public,
            signature,
            ident,
        }
    }

    pub fn new<Text: TryInto<url::Url>>(url: Text) -> Result<(Vid, Ed::SigningKey), Text::Error> {
        let secret = Ed::SigningKey::generate(&mut OsRng);

        Ok((Vid::generate_from_key(url.try_into()?, &secret), secret))
    }
}

#[cfg(test)]
mod test {
    use super::{Error, Identifier, Verifier, Vid};

    #[test]
    fn base64_error() {
        let vid = "hj9g/Rzn8p8WYalsiTyUSEwy+07qFN9FKCDiK2OfFjI5dZDgTVOzxpX2af3fQCABQAFgEA%idJ0GhTk+7USPcF78BUs4bN29ZPOMb0pqCTbCS1Q4LvTqb4dYIECaWvwBwmailto:tsp@tweedegolf.com";
        assert!(matches!(Vid::parse(vid).unwrap_err(), Error::Encoding(_)));
    }

    #[test]
    fn url_error() {
        let vid = "hj9g/Rzn8p8WYalsiTyUSEwy+07qFN9FKCDiK2OfFjI5dZDgTVOzxpX2af3fQCABQAFgEATidJ0GhTk+7USPcF78BUs4bN29ZPOMb0pqCTbCS1Q4LvTqb4dYIECaWvwBw/ailto:tsp@tweedegolf.com";
        assert!(matches!(Vid::parse(vid).unwrap_err(), Error::Transport(_)));
    }

    #[test]
    fn crypto_error() {
        let vid = "hj9g/Rzn8p8WYalsiTyUSEwy+07qFN9FKCDiK2OfFjI5dZDgTVOzxpX2af3fQCABQAFgEATidJ0GhTk+7USPcF78BUs4bN29ZPOMb0pqCTbCS1Q4LvTqb4dYIFCaWvwBwmailto:tsp@tweedegolf.com";
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
            vid.public_key()
                .verify(text.as_bytes(), &vid.signature)
                .unwrap();
        }

        let vid1 = "hj9g/Rzn8p8WYalsiTyUSEwy+07qFN9FKCDiK2OfFjI5dZDgTVOzxpX2af3fQCABQAFgEATidJ0GhTk+7USPcF78BUs4bN29ZPOMb0pqCTbCS1Q4LvTqb4dYIECaWvwBwmailto:tsp@tweedegolf.com";
        let vid2 = &Vid::new("mailto:tsp@tweedegolf.com").unwrap().0.display();
        check_vid(vid1, "mailto:tsp@tweedegolf.com");
        check_vid(vid2, "mailto:tsp@tweedegolf.com");
        assert_ne!(vid1, vid2);
    }
}
