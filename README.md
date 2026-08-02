# TinyCrypT

![Drawing of Penelope, After Attic Red Figure](https://upload.wikimedia.org/wikipedia/commons/0/03/Adolphe_Yvon_Penelope_%28cropped_to_image%29.jpg)

Collection of classical cryptographic primitives written in portable C90 (with optional GNU extensions also supported by Clang) with no dependencies (including the standard library), optimized for correctness, soundness, portability, and speed in that order.

## Algorithms

- ChaCha20-Poly1305 for combined encryption and MAC
- KangarooTwelve128 and TurboSHAKE128 for extendable-output hashing
- Curve25519 for elliptic-curve Diffie-Hellman key exchange
- SHA-256 and SHA-512 for hashing, ECDH, and Ed25519
- Ed25519 for EdDSA

## Testing Validations

- The SHA-2 implementations pass all 586 NIST-provided test cases.
- The ChaCha20-Poly1305 implementations pass the test vectors provided in the RFC (integrating Wycheproof tests is in progress).
- The Ed25519 implementation passes all 1024 provided test cases.
- The Curve25519 implementation passes all Wycheproof test cases.

## Proof Validations

- The KangarooTwelve128 and TurboSHAKE128 implementations can be proven to be memory-sound using Frama-C with the WP plugin (provided one follows the contract outlined in the header).
- The 64-bit Curve25519 implementation can be proven to be constant time and avoid cache timing side channels when compiled for x86-64 (with or without AVX2) using BINSEC/SSE (note that the 32-bit implementation is **not yet constant time**).
- The 64-bit and 32-bit SHA-2 implementations can be proven to be constant time (except in the length of the input data, of course) and avoid cache timing side channels for input lengths up to 3KiB when compiled for x86-64 (with or without AVX2) or ARM Cortex-A, again using BINSEC/SSE (proving this for other builds is in progress, the proof takes a long time).

## Benchmarking

- The 64-bit implementation of Ed25519 (automatically compiled against when the target platform supports `__uint128_t`) is able to generate a signature on 16KiB of data in 0.12ms on an Intel Core i3-1315U processor (single core).
- The SIMD implementation of ChaCha20-Poly1305 (which requires GNU vector extensions, which are supported in Clang) is able to encrypt, authenticate, decrypt, and verify 1GiB of data in 0.81s on an Intel Core i3-1315U processor (single core).

## Current Issues

- Frama-C/WP memory soundness proofs are still being developed for most of the codebase, and that includes occasionally finding bugs.
- There is currently no CI pipeline, and all tests and proofs are done ad-hoc during development.
- The Ed25519 implementation, whether for 32- or 64-bit, is vulnerable to cache timing attacks due to the way a lookup table is addressed. This can be avoided at the cost of a significant amount of performance by building with the flag `-DTCT_LOWMEM`.
- The 32-bit Curve25519 implementation is not yet constant time and relies on relatively slow Barrett reductions.
