mod api;
mod simple_vid;

pub use api::{Error, Identifier};
pub use simple_vid::Vid as SelfSignedVid;

#[cfg(test)]
mod test {
    use super::{Identifier, SelfSignedVid};

    fn reparse_test<KemType: hpke::Kem, Ident: Identifier<KemType> + Eq + std::fmt::Debug>(
        id: &Ident,
    ) {
        let display = id.display();
        let vid = Ident::parse(display.as_str()).unwrap();
        assert_eq!(&vid, id);
    }

    #[test]
    fn simple_test() {
        let vid = SelfSignedVid::new("mailto:tsp@tweedegolf.com").unwrap().0;
        reparse_test(&vid);
    }
}
