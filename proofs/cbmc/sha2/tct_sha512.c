#include "tinycrypt/sha2.h"
#include <stdint.h>

void
harness (void)
{
  uint8_t *input;
  uint64_t input_len;
  uint8_t *output;
  tct_sha512 (input, input_len, output);
}
