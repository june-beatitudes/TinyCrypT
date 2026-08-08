#ifndef TCT_SHAKE_H
#define TCT_SHAKE_H

#include <stdint.h>

#define TCT_KP1600_STATE_LEN 200

/// Initialize the SHAKE state (invariant of the level)
void tct_shake_init (uint8_t state[TCT_KP1600_STATE_LEN]);

/// Absorb (200 - 2 * level) bytes into the state, level being 128 or
/// 256.
void tct_shake_absorb (uint8_t state[TCT_KP1600_STATE_LEN],
                       const uint8_t *chunk, const uint16_t level);

/// Squeeze out output_len bytes from the state (destructively to said state),
/// with the level being 128 or 256
void tct_shake_squeeze_destructive (uint8_t state[TCT_KP1600_STATE_LEN],
                                    uint8_t *output, const uint64_t output_len,
                                    const uint16_t level);

/// End-to-end SHAKE as specified in FIPS 202
void tct_shake_full (const uint8_t *data, const uint64_t data_len,
                     const uint16_t level, uint8_t *output,
                     const uint64_t output_len);

#endif
