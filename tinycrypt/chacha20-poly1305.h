#ifndef TNT_CC20_P1305_H
#define TNT_CC20_P1305_H

#include <stdint.h>

/// Implements the AEAD-ChaCha20-Poly1305 algorithm defined in RFC 8439
void tnt_aead_chacha20_poly1305 (const uint8_t *aad, const uint64_t aad_len,
                                 const uint8_t *key, const uint8_t *nonce,
                                 const uint8_t *plaintext,
                                 const uint64_t plaintext_len,
                                 uint8_t *cipher_out, uint8_t *mac_out);

#endif