use vid::Identifier;
use vid::SelfSignedVid;

fn main() {
    let (vid, _) = SelfSignedVid::new("mailto:tsp@tweedegolf.com").unwrap();
    println!("{}", serde_json::to_string(&vid).unwrap());
    println!("{:?}", vid.display());
}
