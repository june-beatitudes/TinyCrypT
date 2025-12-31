#ifndef TCT_SHA2_H
#define TCT_SHA2_H

#include <stdint.h>

/// Implements the NIST SHA-256 algorithm
void tct_sha256 (const uint8_t *data, uint64_t data_len, uint8_t *hash_out);

/// Implements the NIST SHA-512 algorithm
void tct_sha512 (const uint8_t *data, uint64_t data_len, uint8_t *hash_out);

#endif