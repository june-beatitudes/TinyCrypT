# TinyCrypT

Personal-use implementations of various cryptographic algorithms (NOT FOR PRODUCTION USE)

## Algorithms
- ChaCha20-Poly1305 for combined encryption and MAC
- KangarooTwelve128 for hashing
- X25519 for elliptic-curve Diffie-Hellman key exchange
- SHA-256 and SHA-512 for hashing, ECDH, and Ed25519
- Ed25519 for EdDSA

## Known Vulnerabilities
The CC20-P1305 implementation was not designed with side-channel attacks in mind. Rewriting it to perform actions in constant time is a goal currently being undertaken (after unit tests are in place).