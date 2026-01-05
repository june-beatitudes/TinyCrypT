# TinyCrypT

Personal-use implementations of various cryptographic algorithms (NOT INTENDED FOR PRODUCTION USE)

## Algorithms
- ChaCha20-Poly1305 for combined encryption and MAC
- KangarooTwelve128 for hashing
- X25519 for elliptic-curve Diffie-Hellman key exchange
- SHA-256 and SHA-512 for hashing, ECDH, and Ed25519
- Ed25519 for EdDSA

## Known Vulnerabilities
The CC20-P1305 implementation was not designed with side-channel attacks in mind. Rewriting it to perform actions in constant time is a goal currently being undertaken (after unit tests are in place).

## Testing Validations
- The SHA-2 implementations pass all 586 NIST-provided test cases without memory violations (according to `valgrind`).
- The Ed25519 implementation passes all 1024 provided test cases without memory violations (according to `valgrind`).

## Benchmarking
- The 64-bit implementation of Ed25519 (automatically compiled against when the target platform supports `__uint128_t`) is able to generate a signature in 0.086ms on an Intel Core i3-1315U processor.