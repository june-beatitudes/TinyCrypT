#include "tinycrypt/ed25519.h"
#include <stdint.h>
#include <stdio.h>

int
main (int argc, const char **argv)
{
  uint32_t lut[15360];
  tct_ed25519_pctable_gen (lut);
  printf ("#include <stdint.h>\n");
  printf ("const static uint32_t PRECOMPUTE_TABLE[15360] = {\n    ");
  for (unsigned int i = 0; i < 15360; ++i)
    {
      printf ("0x%x, ", lut[i]);
      if (i % 8 == 7)
        {
          printf ("\n    ");
        }
    }
  printf ("};\n");
  return 0;
}