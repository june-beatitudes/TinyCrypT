#include "tinycrypt/sha2.h"
#include <stdint.h>

void
harness (void)
{
  uint64_t input_len;
  __CPROVER_assume(input_len <= 0x7fffffffffffffff);
  const uint8_t input[input_len];
  uint8_t output[TCT_SHA512_DIGEST_LEN];
  tct_sha512 (input, input_len, output);
}
