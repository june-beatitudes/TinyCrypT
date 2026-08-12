#include <stdbool.h>
#include <stdint.h>

#include "tinycrypt/internal/cbmc.h"
#include "tinycrypt/sha3.h"

static uint64_t
rotl64 (uint64_t x, uint32_t c) __func_contract__ (
  requires (0 < c % 64)
)
{
  return (x << (c % 64)) | (x >> (64 - (c % 64)));
}

static uint64_t
from_le64 (const uint8_t *x) __func_contract__ (
  requires (is_fresh (x, 8))
)
{
  uint64_t u = 0x0;
  for (unsigned int i = 0; i < 8; ++i)
    __loop_contract__ (
      loop_invariant (i <= 8)
      loop_decreases (8 - i)
    )
    {
      u <<= 8;
      u |= x[7 - i];
    }
  return u;
}

static void
to_le64 (uint64_t u, uint8_t *x)
    __func_contract__ (
      requires (is_writable (x, 8))
      assigns (memory_slice (x, 8))
    )
{
  for (unsigned int i = 0; i < 8; ++i)
    __loop_contract__ (
      assigns (memory_slice (x, 8); i; u)
      loop_invariant (i <= 8)
      loop_decreases (8 - i)
    )
    {
      x[i] = u & 0xFF;
      u >>= 8;
    }
}

static const uint64_t RC[24]
    = { 0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008 };

static void
kp (uint8_t state[TCT_KP1600_STATE_LEN], uint8_t rounds)
    __func_contract__ (
      assigns (memory_slice (state, TCT_KP1600_STATE_LEN))
      requires (is_fresh (state, TCT_KP1600_STATE_LEN))
      requires (rounds <= 24)
    )
{
  uint64_t lanes[5][5];
  for (unsigned int x = 0; x < 5; ++x)
    __loop_contract__ (
      loop_invariant (x <= 5)
      loop_decreases (5 - x)
    )
    {
      for (unsigned int y = 0; y < 5; ++y)
        __loop_contract__ (
          loop_invariant (y <= 5)
          loop_decreases (5 - y)
        )
        {
          lanes[x][y] = from_le64 (&state[8 * (x + 5 * y)]);
        }
    }
  for (unsigned int round = 0; round < rounds; ++round)
    __loop_contract__ (
      loop_invariant (round <= rounds)
      loop_decreases (rounds - round)
    )
    {
      uint64_t C[5];
      uint64_t D[5];
      for (unsigned int x = 0; x < 5; ++x)
        __loop_contract__ (
          loop_invariant (x <= 5)
          loop_decreases (5 - x)
        )
        {
          C[x] = lanes[x][0];
          C[x] ^= lanes[x][1];
          C[x] ^= lanes[x][2];
          C[x] ^= lanes[x][3];
          C[x] ^= lanes[x][4];
        }
      for (unsigned int x = 0; x < 5; ++x)
        __loop_contract__ (
          loop_invariant (x <= 5)
          loop_decreases (5 - x)
        )
        {
          D[x] = C[(x + 4) % 5] ^ rotl64 (C[(x + 1) % 5], 1);
        }
      for (unsigned int y = 0; y < 5; ++y)
        __loop_contract__ (
          loop_invariant (y <= 5)
          loop_decreases (5 - y)
        )
        {
          for (unsigned int x = 0; x < 5; ++x)
            __loop_contract__ (
              loop_invariant (x <= 5)
              loop_decreases (5 - x)
            )
            {
              lanes[x][y] ^= D[x];
            }
        }
      uint64_t x = 1;
      uint64_t y = 0;
      uint64_t current = lanes[x][y];
      for (unsigned int t = 0; t < 24; ++t)
        __loop_contract__ (
          assigns (t; x; y; current; entire_object (lanes))
          loop_invariant (t <= 24)
          loop_invariant (x < 5)
          loop_invariant (y < 5)
          loop_decreases (24 - t)
        )
        {
          uint64_t tmp = x;
          x = y;
          y = (2 * tmp + 3 * y) % 5;
          tmp = current;
          current = lanes[x][y];
          lanes[x][y] = rotl64 (tmp, (t + 1) * (t + 2) / 2);
        }
      uint64_t T[5];
      for (unsigned int y = 0; y < 5; ++y)
        __loop_contract__ (
          assigns (entire_object (T); entire_object (lanes); y)
          loop_invariant (y <= 5)
          loop_decreases (5 - y)
        )
        {
          for (unsigned int x = 0; x < 5; ++x)
            __loop_contract__ (
              assigns (entire_object (T); x)
              loop_invariant (x <= 5)
              loop_decreases (5 - x)
            )
            {
              T[x] = lanes[x][y];
            }
          for (unsigned int x = 0; x < 5; ++x)
            __loop_contract__ (
              assigns (entire_object(lanes); x)
              loop_invariant (x <= 5)
              loop_decreases (5 - x)
            )
            {
              lanes[x][y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5]);
            }
        }
      lanes[0][0] ^= RC[round];
    }
  for (unsigned int y = 0; y < 5; ++y)
    __loop_contract__ (
      assigns (memory_slice (state, TCT_KP1600_STATE_LEN); y)
      loop_invariant (y <= 5)
      loop_decreases (5 - y)
    )
    {
      for (unsigned int x = 0; x < 5; ++x)
        __loop_contract__ (
          assigns (memory_slice (state, TCT_KP1600_STATE_LEN); x)
          loop_invariant (x <= 5)
          loop_decreases (5 - x)
        )
        {
          to_le64 (lanes[x][y], state + y * 40 + x * 8);
        }
    }
}

#define TCT_SHAKE_ROUNDS 24

void
tct_shake_init (uint8_t state[TCT_KP1600_STATE_LEN])
    __func_contract__ (
      requires (is_fresh (state, TCT_KP1600_STATE_LEN))
      assigns (memory_slice (state, TCT_KP1600_STATE_LEN))
    )
{
  for (unsigned int i = 0; i < TCT_KP1600_STATE_LEN; ++i)
    __loop_contract__ (
      loop_invariant (i <= TCT_KP1600_STATE_LEN)
      loop_decreases (TCT_KP1600_STATE_LEN - i)
    )
    {
      state[i] = 0x0;
    }
}

void
tct_shake_absorb (uint8_t state[TCT_KP1600_STATE_LEN], const uint8_t *chunk,
                  const enum tct_shake_level level)
    __func_contract__ (
      requires (is_fresh (state, TCT_KP1600_STATE_LEN))
      requires (is_fresh (chunk, (level == TCT_SHAKE128) ? 168 : 136))
      assigns (memory_slice (state, TCT_KP1600_STATE_LEN))
    )
{
  const uint8_t r = (level == TCT_SHAKE128) ? 168 : 136;
  for (uint8_t i = 0; i < r; ++i)
    __loop_contract__ (
      loop_invariant (i <= r)
      loop_decreases (r - i)
    )
    {
      state[i] ^= chunk[i];
    }
  kp (state, TCT_SHAKE_ROUNDS);
}

void
tct_shake_squeeze_destructive (uint8_t state[TCT_KP1600_STATE_LEN],
                               uint8_t *output, const uint64_t output_len,
                               const enum tct_shake_level level)
    __func_contract__ (
      requires (output_len < 0xffffffffffffffff - 168)
      requires (is_fresh (state, TCT_KP1600_STATE_LEN))
      assigns (memory_slice (state, TCT_KP1600_STATE_LEN))
      requires (is_fresh (output, output_len))
      assigns (memory_slice (output, output_len))
    )
{
  const uint8_t r = (level == TCT_SHAKE128) ? 168 : 136;
  for (uint64_t i = 0; i < output_len; i += r)
    __loop_contract__ (
      loop_invariant (i <= output_len + r)
      loop_decreases (output_len + r - i)
    )
    {
      for (unsigned int j = 0; j < (output_len - i) && j < r; ++j)
        __loop_contract__ (
          loop_invariant (j <= (output_len - i) && j <= r)
          loop_decreases (r - j)
        )
        {
          output[i + j] = state[j];
        }
      kp (state, TCT_SHAKE_ROUNDS);
    }
}

void
tct_shake_full (const uint8_t *data, const uint64_t data_len,
                const enum tct_shake_level level, uint8_t *output,
                const uint64_t output_len)
    __func_contract__ (
      requires (output_len < 0xffffffffffffffff - 168)
      requires (data_len < 0xffffffffffffffff - 168)
      requires (is_fresh (output, output_len))
      requires (is_fresh (data, data_len))
      assigns (memory_slice (output, output_len))
    )
{
  const uint8_t r = (level == TCT_SHAKE128) ? 168 : 136;
  uint8_t state[TCT_KP1600_STATE_LEN];
  tct_shake_init (state);
  uint8_t buf[168];
  for (uint64_t i = 0; i <= data_len; i += r)
    __loop_contract__ (
      assigns (i; memory_slice (buf, r); memory_slice (state, TCT_KP1600_STATE_LEN))
      loop_invariant (i <= data_len + r)
      loop_decreases (data_len + r - i)
    )
    {
      for (uint64_t j = 0; j < r && j < data_len - i; ++j)
        __loop_contract__ (
          assigns (j; memory_slice (buf, r))
          loop_invariant (j <= (data_len - i) && j <= r)
          loop_decreases (r - j)
        )
        {
          buf[j] = data[i + j];
        }
      for (uint64_t j = data_len - i; j < r; ++j)
        __loop_contract__ (
          assigns (j; memory_slice (buf, r))
          loop_invariant (data_len - i <= j && j <= r)
          loop_decreases (r - j)
        )
        {
          buf[j] = 0x0;
          if (j == data_len - i)
            {
              buf[j] |= 0x1f;
            }
          if (j == r - 1)
            {
              buf[j] |= 0x80;
            }
        }
      tct_shake_absorb (state, buf, level);
    }
  tct_shake_squeeze_destructive (state, output, output_len, level);
}
