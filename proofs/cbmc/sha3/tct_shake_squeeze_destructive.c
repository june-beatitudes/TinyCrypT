#include "tinycrypt/sha3.h"
#include <stdint.h>

void
harness (void)
{
  uint8_t *state;
  uint8_t *output;
  uint64_t output_len;
  enum tct_shake_level level;
  tct_shake_squeeze_destructive (state, output, output_len, level);
}
