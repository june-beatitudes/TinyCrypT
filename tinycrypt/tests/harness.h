#ifndef TCT_TEST_HARNESS_H
#define TCT_TEST_HARNESS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/time.h>

struct tct_testing_ctx
{
  size_t tests_passed;
  size_t tests_failed;
  struct timeval start;
  struct timeval end;
};

void tct_testing_init_ctx (struct tct_testing_ctx *ctx);

void tct_testing_assert (struct tct_testing_ctx *ctx, bool value,
                         const char *name);

void tct_testing_start (struct tct_testing_ctx *ctx);

void tct_testing_end (struct tct_testing_ctx *ctx);

#endif