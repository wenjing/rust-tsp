# rust-tsp
Rust implementation of the Trust Spanning Protocol 

## POC Encoding

POC seal-unseal encoding lengths:

Raw data: 133 bytes
CESR: not encodable (no primitives vor encapped key, or VID, no concatenation)
MessagePack: 244 bytes
CBOR: 402 bytes
Custom (see below): 137 bytes

+--------+------------+------------+-------------+-------------+----------+----------+--------------+-----------+------------+
| Field  | Ver. Major | Ver. minor | Snd VID len | Rec VID len | Snd VID  | Rec VID  | Encapped key | Signature | Ciphertext |
+--------+------------+------------+-------------+-------------+----------+----------+--------------+-----------+------------+
| Length | 1 byte     | 1 byte     | 2 bytes     | 2 bytes     | variable | variable | 32 bytes     | 16 bytes  | variable   |
+--------+------------+------------+-------------+-------------+----------+----------+--------------+-----------+------------+
