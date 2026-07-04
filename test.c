#include "tinycrypt/chacha20_poly1305.h"
#include <stdint.h>
#include <stdio.h>

int
main (int argc, char **argv)
{
  const uint8_t KEY[]
      = { 0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31, 0xf3, 0x14, 0xaf,
          0x57, 0xf3, 0xbe, 0x3b, 0x50, 0x06, 0xda, 0x37, 0x1e, 0xce, 0x27,
          0x2a, 0xfa, 0x1b, 0x5d, 0xbd, 0xd1, 0x10, 0x0a, 0x10, 0x07 };
  const uint8_t INPUT[128 * 1024];
  const uint8_t NONCE[] = { 0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a };
  const uint8_t AAD[] = { 0x0 };
  uint8_t actual_output[sizeof (INPUT) + 16];
  for (uint64_t i = 0; i < 1024; ++i)
    {
      tct_aead_chacha20_poly1305_encrypt (AAD, sizeof (AAD), KEY, NONCE, INPUT,
                                          sizeof (INPUT), actual_output,
                                          actual_output + sizeof (INPUT));
    }
  return 0;
}