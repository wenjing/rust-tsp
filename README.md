# rust-tsp
Rust implementation of the Trust Spanning Protocol 

## Crypto

The POC uses HPKE / RFC 9180, specifically: https://github.com/rozbb/rust-hpke
HPKE is IND-CCA2 secure.
See other HPKE implementations: https://github.com/cfrg/draft-irtf-cfrg-hpke#existing-hpke-implementations

## POC Encoding

POC seal-unseal encoding lengths:

Raw data: 133 bytes
CESR: TODO + add code for encapped key
MessagePack: 244 bytes
CBOR: 402 bytes
Custom (see below): 137 bytes

Question: can/should we do encoding agnostic signing

```
+--------+------------+------------+-------------+-------------+----------+----------+--------------+------------+
| Field  | Ver. Major | Ver. minor | Snd VID len | Rec VID len | Snd VID  | Rec VID  | Encapped key | Ciphertext |
+--------+------------+------------+-------------+-------------+----------+----------+--------------+------------+
| Length | 1 byte     | 1 byte     | 2 bytes     | 2 bytes     | variable | variable | 32 bytes     | variable   |
+--------+------------+------------+-------------+-------------+----------+----------+--------------+------------+
```
