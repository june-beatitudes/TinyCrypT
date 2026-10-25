#ifndef TCT_SHA2_H
#define TCT_SHA2_H

#include "tinycrypt/internal/cbmc.h"
#include <stdint.h>

#define TCT_SHA256_DIGEST_LEN 32
#define TCT_SHA512_DIGEST_LEN 64

/// Implements the NIST SHA-256 algorithm
void tct_sha256 (const uint8_t *data, uint64_t data_len, uint8_t *hash_out)
    __func_contract__(
      requires(is_readable(data, data_len))
      requires(is_writable(hash_out, TCT_SHA256_DIGEST_LEN))
      requires(data_len <= 0xfffffffffffffff)
      assigns(memory_slice(hash_out, TCT_SHA256_DIGEST_LEN))
    );

/// Implements the NIST SHA-512 algorithm
void tct_sha512 (const uint8_t *data, uint64_t data_len, uint8_t *hash_out)
    __func_contract__(
      requires(data_len <= 0x7fffffffffffffff)
      requires(is_readable(data, data_len))
      requires(is_writable(hash_out, TCT_SHA512_DIGEST_LEN))
      assigns(memory_slice(hash_out, TCT_SHA512_DIGEST_LEN))
    );

#endif
