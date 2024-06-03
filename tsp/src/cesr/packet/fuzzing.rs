use super::*;

#[derive(Debug)]
pub struct Wrapper(pub Payload<'static, Vec<u8>, Vec<u8>>);

impl<'a> arbitrary::Arbitrary<'a> for Wrapper {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        const DIGEST: [u8; 32] = {
            let mut buf = [0; 32];
            let mut i = 0;
            while i < buf.len() {
                buf[i] = i as u8;
                i += 1;
            }

            buf
        };

        const SIGNING: [u8; 32] = DIGEST;

        const ENCRYPTING: [u8; 32] = {
            let mut buf = [0; 32];
            let mut i = 0;
            while i < buf.len() {
                buf[i] = 32 + i as u8;
                i += 1;
            }

            buf
        };

        const PAIRED_KEYS: PairedKeys<'static> = PairedKeys {
            signing: &SIGNING,
            encrypting: &ENCRYPTING,
        };

        #[derive(arbitrary::Arbitrary)]
        enum Variants {
            GenericMessage,
            NestedMessage,
            RoutedMessage,
            DirectRelationProposal,
            DirectRelationAffirm,
            NestedRelationProposal,
            NestedRelationAffirm,
            RelationshipCancel,
        }

        #[allow(dead_code)]
        fn check_exhaustive(payload: Payload<Vec<u8>, Vec<u8>>) -> Variants {
            match payload {
                Payload::GenericMessage(_) => Variants::GenericMessage,
                Payload::NestedMessage(_) => Variants::NestedMessage,
                Payload::RoutedMessage(_, _) => Variants::RoutedMessage,
                Payload::DirectRelationProposal { .. } => Variants::DirectRelationProposal,
                Payload::DirectRelationAffirm { .. } => Variants::DirectRelationAffirm,
                Payload::NestedRelationProposal { .. } => Variants::NestedRelationProposal,
                Payload::NestedRelationAffirm { .. } => Variants::NestedRelationAffirm,
                Payload::RelationshipCancel { .. } => Variants::RelationshipCancel,
            }
        }

        let variant = Variants::arbitrary(u)?;

        use arbitrary::Arbitrary;
        let payload = match variant {
            Variants::GenericMessage => Payload::GenericMessage(Arbitrary::arbitrary(u)?),
            Variants::NestedMessage => Payload::NestedMessage(Arbitrary::arbitrary(u)?),
            Variants::RoutedMessage => {
                Payload::RoutedMessage(Arbitrary::arbitrary(u)?, Arbitrary::arbitrary(u)?)
            }
            Variants::DirectRelationProposal => Payload::DirectRelationProposal {
                nonce: Nonce(Arbitrary::arbitrary(u)?),
                hops: Arbitrary::arbitrary(u)?,
            },
            Variants::DirectRelationAffirm => Payload::DirectRelationAffirm { reply: &DIGEST },
            Variants::NestedRelationProposal => Payload::NestedRelationProposal {
                public_keys: PAIRED_KEYS,
                new_vid: Arbitrary::arbitrary(u)?,
            },
            Variants::NestedRelationAffirm => Payload::NestedRelationAffirm {
                reply: &DIGEST,
                public_keys: PAIRED_KEYS,
                new_vid: Arbitrary::arbitrary(u)?,
            },
            Variants::RelationshipCancel => Payload::RelationshipCancel {
                nonce: Nonce(Arbitrary::arbitrary(u)?),
                reply: &DIGEST,
            },
        };

        Ok(Wrapper(payload))
    }
}

impl<'a> PartialEq<Payload<'a, &'a [u8], &'a [u8]>> for Wrapper {
    fn eq(&self, other: &Payload<'a, &'a [u8], &'a [u8]>) -> bool {
        match (&self.0, other) {
            (Payload::GenericMessage(l0), Payload::GenericMessage(r0)) => l0 == r0,
            (Payload::NestedMessage(l0), Payload::NestedMessage(r0)) => l0 == r0,
            (Payload::RoutedMessage(l0, l1), Payload::RoutedMessage(r0, r1)) => {
                l0 == r0 && l1 == r1
            }
            (
                Payload::DirectRelationProposal {
                    nonce: l_nonce,
                    hops: l_hops,
                },
                Payload::DirectRelationProposal {
                    nonce: r_nonce,
                    hops: r_hops,
                },
            ) => l_nonce.0 == r_nonce.0 && l_hops == r_hops,
            (
                Payload::DirectRelationAffirm { reply: l_reply },
                Payload::DirectRelationAffirm { reply: r_reply },
            ) => l_reply == r_reply,
            (
                Payload::NestedRelationProposal {
                    public_keys: l_public_keys,
                    new_vid: l_vid,
                },
                Payload::NestedRelationProposal {
                    public_keys: r_public_keys,
                    new_vid: r_vid,
                },
            ) => {
                l_public_keys.signing == r_public_keys.signing
                    && l_public_keys.encrypting == r_public_keys.encrypting
                    && l_vid == r_vid
            }
            (
                Payload::NestedRelationAffirm {
                    reply: l_reply,
                    public_keys: l_public_keys,
                    new_vid: l_vid,
                },
                Payload::NestedRelationAffirm {
                    reply: r_reply,
                    public_keys: r_public_keys,
                    new_vid: r_vid,
                },
            ) => {
                l_reply == r_reply
                    && (l_public_keys.signing == r_public_keys.signing
                        && l_public_keys.encrypting == r_public_keys.encrypting)
                    && l_vid == r_vid
            }

            (
                Payload::RelationshipCancel {
                    nonce: l_nonce,
                    reply: l_reply,
                },
                Payload::RelationshipCancel {
                    nonce: r_nonce,
                    reply: r_reply,
                },
            ) => l_nonce.0 == r_nonce.0 && l_reply == r_reply,
            _ => false,
        }
    }
}
