#ifndef TCT_KT128_H
#define TCT_KT128_H

#include <stdint.h>

/// Implements the KangarooTwelve128 hashing algorithm as defined in RFC 8961
void tct_kangarootwelve128 (const uint8_t *input, const uint64_t input_len,
                            const uint8_t *custom_str, const uint64_t cs_len,
                            uint8_t *output, const uint64_t output_len);

#define TCT_TURBOSHAKE128_STATE_LEN 200

/// Initialize TurboSHAKE128 state
void tct_turboshake128_init (uint8_t state[TCT_TURBOSHAKE128_STATE_LEN]);

/// Absorb new data into the TurboSHAKE128 state
void tct_turboshake128_absorb (uint8_t state[TCT_TURBOSHAKE128_STATE_LEN],
                               const uint8_t *data, const uint64_t data_len,
                               const uint8_t separation_byte);

/// Squeeze new hashed data out of the TurboSHAKE128 state, destructively (to
/// the state)
void tct_turboshake128_squeeze_destructive (
    uint8_t state[TCT_TURBOSHAKE128_STATE_LEN], uint8_t *output,
    const uint64_t output_len);

#endif