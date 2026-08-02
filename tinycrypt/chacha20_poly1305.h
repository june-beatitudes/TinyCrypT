#ifndef TNT_CC20_P1305_H
#define TNT_CC20_P1305_H

#include <stdbool.h>
#include <stdint.h>

/// Implements the AEAD-ChaCha20-Poly1305 encryption and MAC algorithm defined
/// in RFC 8439
void tct_aead_chacha20_poly1305_encrypt (
    const uint8_t *aad, const uint64_t aad_len, const uint8_t *key,
    const uint8_t *nonce, const uint8_t *plaintext,
    const uint64_t plaintext_len, uint8_t *cipher_out, uint8_t *mac_out);

/// Decrypts and verifies an AEAD-ChaCha20-Poly1305 frame
bool tct_aead_chacha20_poly1305_decrypt_and_verify (
    const uint8_t *aad, const uint64_t aad_len, const uint8_t *key,
    const uint8_t *nonce, const uint8_t *frame, const uint64_t ciphertext_len,
    uint8_t *plaintext_out);

/// Encrypts or decrypts a ChaCha20-encrypted stream (it's symmetric, so
/// they're the same essential operation)
void tct_chacha20_encrypt_or_decrypt (const uint8_t *key,
                                      const uint32_t counter,
                                      const uint8_t *nonce, const uint8_t *in,
                                      const uint64_t in_len, uint8_t *out);

#endif
