#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "tinycrypt/sha2.h"
#include "tinycrypt/tests/harness.h"

int
main (int argc, const char **argv)
{
  struct tct_testing_ctx ctx;
  tct_testing_init_ctx (&ctx);
  printf ("Beginning tests\n");
  tct_testing_start (&ctx);

  uint8_t buf[32];
  tct_sha256 (NULL, 0, buf);
  uint8_t reference[] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
    0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
    0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
  };
  tct_testing_assert (&ctx, !memcmp (buf, reference, sizeof (buf)),
                      "Empty SHA-256");

  tct_testing_end (&ctx);
  printf ("%lu tests passed, %lu tests failed, %lu microseconds elapsed\n",
          ctx.tests_passed, ctx.tests_failed,
          (1000000 * ctx.end.tv_sec + ctx.end.tv_usec)
              - (1000000 * ctx.start.tv_sec + ctx.start.tv_usec));
}