#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/time.h>

#include "tinycrypt/tests/harness.h"

void
tct_testing_init_ctx (struct tct_testing_ctx *ctx)
{
  ctx->tests_passed = 0;
  ctx->tests_failed = 0;
}

void
tct_testing_assert (struct tct_testing_ctx *ctx, bool value, const char *name)
{
  if (!value)
    {
      ctx->tests_failed++;
      printf ("Test '%s' failed!\n", name);
    }
  else
    {
      ctx->tests_passed++;
    }
}

void
tct_testing_start (struct tct_testing_ctx *ctx)
{
  gettimeofday (&(ctx->start), NULL);
}

void
tct_testing_end (struct tct_testing_ctx *ctx)
{
  gettimeofday (&(ctx->end), NULL);
}