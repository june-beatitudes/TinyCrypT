#include "tinycrypt/memory.h"
#include "tinycrypt/internal/cbmc.h"
#include <stdint.h>

void
tct_wipe (volatile uint8_t *p, uint64_t n)
{
  for (uint64_t i = 0; i < n; ++i)
    __loop_contract__(
      assigns(i; memory_slice(p, n))
      loop_invariant(0 <= i && i <= n)
      loop_decreases(n - i)
    )
    {
      p[i] = 0x0;
    }
}

bool
tct_mem_equals (const volatile uint8_t *a, const volatile uint8_t *b,
                uint64_t n)
{
  uint8_t acc = 0x0;
  for (uint64_t i = 0; i < n; ++i)
    __loop_contract__(
      assigns(i; acc)
      loop_invariant(0 <= i && i <= n)
      loop_decreases(n - i)
    )
    {
      acc |= a[i] ^ b[i];
    }
  return acc == 0x0;
}
