#ifndef TCT_X25519_H
#define TCT_X25519_H

#include <stdint.h>

#define TCT_X25519_PRIVKEY_LEN 32
#define TCT_X25519_PUBKEY_LEN 32
#define TCT_X25519_SHARE_LEN 32

/// Implements the X25519 ECDH key derivation function as described in RFC 7748
void tct_x25519 (const uint8_t *key, const uint8_t *u, uint8_t *out);

#endif
