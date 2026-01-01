#ifndef TCT_ED25519_H
#define TCT_ED25519_H

#include <stdbool.h>
#include <stdint.h>

/// Generates an Ed25519 public key based on a corresponding private key, as
/// described in RFC 8032.
void tct_ed25519_keygen (const uint8_t *privkey, uint8_t *pubkey);

/// Generates an Ed25519 signature as described in RFC 8032. Requires a working
/// buffer of at least `msg_len + 64` bytes.
void tct_ed25519_sign (const uint8_t *msg, const uint64_t msg_len,
                       const uint8_t *privkey, const uint8_t *pubkey,
                       uint8_t *working_buf, uint8_t *signature);

/// Implements the Ed25519 signature verification algorithm described in RFC
/// 8032. Requires a working buffer of at least `msg_len + 64` bytes.
bool tct_ed25519_verify (const uint8_t *pubkey, const uint8_t *msg,
                         const uint64_t msg_len, uint8_t *working_buf,
                         const uint8_t *signature);

#endif