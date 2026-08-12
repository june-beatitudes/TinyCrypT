#include "tinycrypt/sha3.h"
#include <stdint.h>

void
harness (void)
{
  uint8_t *input;
  uint64_t input_len;
  uint8_t *output;
  uint64_t output_len;
  enum tct_shake_level level;
  tct_shake_full (input, input_len, level, output, output_len);
}
