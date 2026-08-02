#ifndef TCT_ED25519_H
#define TCT_ED25519_H

#include <stdbool.h>
#include <stdint.h>

#define TCT_ED25519_PRIVKEY_LEN 32
#define TCT_ED25519_PUBKEY_LEN 32
#define TCT_ED25519_SIGNATURE_LEN 64

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

/// Constructs a memory-speed-tradeoff lookup table for use in Ed25519
/// verifications, similar (but larger by ~2x) to the method described in
/// https://ed25519.cr.yp.to/ed25519-20110926.pdf.
void tct_ed25519_pctable_gen (uint32_t *out);

void tct_ed25519_pctable_gen_64bit (uint64_t *out);

#endif
