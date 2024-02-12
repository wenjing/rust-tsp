# rust-tsp
Rust implementation of the Trust Spanning Protocol 

## Crypto

The POC uses HPKE / RFC 9180, specifically: https://github.com/rozbb/rust-hpke
HPKE is IND-CCA2 secure.
See other HPKE implementations: https://github.com/cfrg/draft-irtf-cfrg-hpke#existing-hpke-implementations

## Benches

Full TSP:
```
seal_unseal_message: [312.26 µs 312.94 µs 314.14 µs]
```

TSP without outer signature:
```
seal_unseal_message: [287.56 µs 287.75 µs 287.97 µs]
```

TSP with HPKE Base:
```
seal_unseal_message: [211.75 µs 211.91 µs 212.08 µs]
```

TSP without outer signature in HPKE Base:
```
seal_unseal_message: [156.90 µs 157.12 µs 157.37 µs]
```

TSP with signature only:
```
seal_unseal_message: [53.926 µs 54.006 µs 54.112 µs]
```
