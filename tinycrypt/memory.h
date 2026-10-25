#ifndef TCT_MEMORY_H
#define TCT_MEMORY_H

#include "tinycrypt/internal/cbmc.h"
#include <stdbool.h>
#include <stdint.h>

void tct_wipe (volatile uint8_t *p, uint64_t n)
    __func_contract__(
      requires(is_writable(p, n))
      assigns(memory_slice(p, n))
    );

bool tct_mem_equals (const volatile uint8_t *a, const volatile uint8_t *b,
                     uint64_t n)
    __func_contract__(
      requires(is_readable(a, n))
      requires(is_readable(b, n))
    );

#endif
