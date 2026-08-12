#include "tinycrypt/sha3.h"

#include <stdint.h>

void
harness (void)
{
  uint8_t *state;
  tct_shake_init (state);
}
