#ifndef TCT_KT128_H
#define TCT_KT128_H

#include <stdint.h>

/// Implements the KangarooTwelve128 hashing algorithm as defined in RFC 8961
void tct_kangarootwelve128 (const uint8_t *input, const uint64_t input_len,
                            const uint8_t *custom_str, const uint64_t cs_len,
                            uint8_t *output, const uint64_t output_len);

#endif