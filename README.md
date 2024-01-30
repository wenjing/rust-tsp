# rust-tsp
Rust implementation of the Trust Spanning Protocol 

## Crypto

The POC uses HPKE / RFC 9180, specifically: https://github.com/rozbb/rust-hpke
HPKE is IND-CCA2 secure.
See other HPKE implementations: https://github.com/cfrg/draft-irtf-cfrg-hpke#existing-hpke-implementations
