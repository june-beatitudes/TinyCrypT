#include <stdbool.h>
#include <stdio.h>

#include "tinycrypt/tests/harness.h"

int
main (int argc, const char **argv)
{
  struct tct_testing_ctx ctx;
  tct_testing_init_ctx (&ctx);
  printf ("Beginning tests\n");
  tct_testing_start (&ctx);

  // Tests go here

  tct_testing_end (&ctx);
  printf ("%lu tests passed, %lu tests failed, %lu microseconds elapsed\n",
          ctx.tests_passed, ctx.tests_failed,
          (1000000 * ctx.end.tv_sec + ctx.end.tv_usec)
              - (1000000 * ctx.start.tv_sec + ctx.start.tv_usec));
}