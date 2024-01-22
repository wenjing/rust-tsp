mod api;
mod simple_vid;

use api::Identifier;
use simple_vid::Vid;

fn main() {
    let vid = Vid::new("mailto:tsp@tweedegolf.com").unwrap().0.display();
    println!("{vid}");
    println!("{:?}", Vid::parse(vid.as_str()).unwrap());
}
