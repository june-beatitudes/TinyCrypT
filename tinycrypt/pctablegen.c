#include "tinycrypt/ed25519.h"
#include <stdint.h>
#include <stdio.h>

int
main (int argc, const char **argv)
{
  uint8_t lut[61440];
  tct_ed25519_pctable_gen (lut);
  printf ("#include <stdint.h>\n");
  printf ("const static uint8_t PRECOMPUTE_TABLE[61440] = {\n    ");
  for (unsigned int i = 0; i < 61440; ++i)
    {
      printf ("0x%02x, ", lut[i]);
      if (i % 16 == 15)
        {
          printf ("\n    ");
        }
    }
  printf ("};\n");
  return 0;
}