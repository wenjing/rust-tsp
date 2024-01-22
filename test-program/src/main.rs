use vid::SelfSignedVid;

fn main() {
    let (vid, _) = SelfSignedVid::new("mailto:tsp@tweedegolf.com").unwrap();
    println!("{vid:?}");
}
