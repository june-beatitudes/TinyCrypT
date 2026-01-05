#include "tinycrypt/ed25519.h"
#include <stdint.h>
#include <stdio.h>

int
main (int argc, const char **argv)
{
  uint64_t lut[7680];
  tct_ed25519_pctable_gen_64bit (lut);
  printf ("#include <stdint.h>\n");
  printf ("const static uint64_t PRECOMPUTE_TABLE[7680] = {\n    ");
  for (unsigned int i = 0; i < 7680; ++i)
    {
      printf ("0x%lx, ", lut[i]);
      if (i % 8 == 7)
        {
          printf ("\n    ");
        }
    }
  printf ("};\n");
  return 0;
}