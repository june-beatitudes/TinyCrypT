#include "tinycrypt/sha3.h"
#include <stdint.h>

void
harness (void)
{
  uint8_t *state;
  uint8_t *chunk;
  enum tct_shake_level level;
  tct_shake_absorb (state, chunk, level);
}
