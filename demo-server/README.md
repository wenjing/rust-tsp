# TSP demo server

This server wil simulate a transport layer using websockets.
It serves a web page that enables a user to create and verify identities.
All cryptographic operations, like sealing and opening messages, happens on the
server on a per-client basis (clients cannot access each other's key material).
