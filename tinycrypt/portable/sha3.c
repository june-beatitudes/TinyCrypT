#include <stdbool.h>
#include <stdint.h>

#include "tinycrypt/sha3.h"

static uint64_t
rotl64 (uint64_t x, uint32_t c) __CPROVER_requires (0 < c % 64)
{
  return (x << (c % 64)) | (x >> (64 - (c % 64)));
}

static uint64_t
from_le64 (const uint8_t *x) __CPROVER_requires (__CPROVER_is_fresh (x, 8))
{
  uint64_t u = 0x0;
  for (unsigned int i = 0; i < 8; ++i)
    __CPROVER_loop_invariant (i <= 8) __CPROVER_decreases (8 - i)
    {
      u <<= 8;
      u |= x[7 - i];
    }
  return u;
}

static void
to_le64 (uint64_t u, uint8_t *x) __CPROVER_requires (__CPROVER_w_ok (x, 8))
    __CPROVER_assigns (__CPROVER_object_upto (x, 8))
{
  for (unsigned int i = 0; i < 8; ++i)
    __CPROVER_assigns (__CPROVER_object_upto (x, 8), i, u)
        __CPROVER_loop_invariant (i <= 8) __CPROVER_decreases (8 - i)
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
    __CPROVER_assigns (__CPROVER_object_upto (state, TCT_KP1600_STATE_LEN))
        __CPROVER_requires (__CPROVER_is_fresh (state, TCT_KP1600_STATE_LEN))
            __CPROVER_requires (rounds <= 24)
{
  uint64_t lanes[5][5];
  for (unsigned int x = 0; x < 5; ++x)
    __CPROVER_loop_invariant (x <= 5) __CPROVER_decreases (5 - x)
    {
      for (unsigned int y = 0; y < 5; ++y)
        __CPROVER_loop_invariant (y <= 5) __CPROVER_decreases (5 - y)
        {
          lanes[x][y] = from_le64 (&state[8 * (x + 5 * y)]);
        }
    }
  for (unsigned int round = 0; round < rounds; ++round)
    __CPROVER_loop_invariant (round <= rounds)
        __CPROVER_decreases (rounds - round)
    {
      uint64_t C[5];
      uint64_t D[5];
      for (unsigned int x = 0; x < 5; ++x)
        __CPROVER_loop_invariant (x <= 5) __CPROVER_decreases (5 - x)
        {
          C[x] = lanes[x][0];
          C[x] ^= lanes[x][1];
          C[x] ^= lanes[x][2];
          C[x] ^= lanes[x][3];
          C[x] ^= lanes[x][4];
        }
      for (unsigned int x = 0; x < 5; ++x)
        __CPROVER_loop_invariant (x <= 5) __CPROVER_decreases (5 - x)
        {
          D[x] = C[(x + 4) % 5] ^ rotl64 (C[(x + 1) % 5], 1);
        }
      for (unsigned int y = 0; y < 5; ++y)
        __CPROVER_loop_invariant (y <= 5) __CPROVER_decreases (5 - y)
        {
          for (unsigned int x = 0; x < 5; ++x)
            __CPROVER_loop_invariant (x <= 5) __CPROVER_decreases (5 - x)
            {
              lanes[x][y] ^= D[x];
            }
        }
      uint64_t x = 1;
      uint64_t y = 0;
      uint64_t current = lanes[x][y];
      for (unsigned int t = 0; t < 24; ++t)
        __CPROVER_assigns (t, x, y, current, __CPROVER_object_whole (lanes))
            __CPROVER_loop_invariant (t <= 24) __CPROVER_loop_invariant (x < 5)
                __CPROVER_loop_invariant (y < 5) __CPROVER_decreases (24 - t)
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
        __CPROVER_assigns (__CPROVER_object_whole (T),
                           __CPROVER_object_whole (lanes), y)
            __CPROVER_loop_invariant (y <= 5) __CPROVER_decreases (5 - y)
        {
          for (unsigned int x = 0; x < 5; ++x)
            __CPROVER_assigns (__CPROVER_object_whole (T), x)
                __CPROVER_loop_invariant (x <= 5) __CPROVER_decreases (5 - x)
            {
              T[x] = lanes[x][y];
            }
          for (unsigned int x = 0; x < 5; ++x)
            __CPROVER_assigns (lanes[0][y], lanes[1][y], lanes[2][y],
                               lanes[3][y], lanes[4][y], x)
                __CPROVER_loop_invariant (x <= 5) __CPROVER_decreases (5 - x)
            {
              lanes[x][y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5]);
            }
        }
      lanes[0][0] ^= RC[round];
    }
  for (unsigned int y = 0; y < 5; ++y)
    __CPROVER_assigns (__CPROVER_object_upto (state, TCT_KP1600_STATE_LEN), y)
        __CPROVER_loop_invariant (y <= 5) __CPROVER_decreases (5 - y)
    {
      for (unsigned int x = 0; x < 5; ++x)
        __CPROVER_assigns (__CPROVER_object_upto (state, TCT_KP1600_STATE_LEN),
                           x) __CPROVER_loop_invariant (x <= 5)
            __CPROVER_decreases (5 - x)
        {
          to_le64 (lanes[x][y], state + y * 40 + x * 5);
        }
    }
}

#define TCT_SHAKE_ROUNDS 24

void
tct_shake_init (uint8_t state[TCT_KP1600_STATE_LEN])
    __CPROVER_requires (__CPROVER_is_fresh (state, TCT_KP1600_STATE_LEN))
        __CPROVER_assigns (__CPROVER_object_upto (state, TCT_KP1600_STATE_LEN))
{
  for (unsigned int i = 0; i < TCT_KP1600_STATE_LEN; ++i)
    __CPROVER_loop_invariant (i <= TCT_KP1600_STATE_LEN)
        __CPROVER_decreases (TCT_KP1600_STATE_LEN - i)
    {
      state[i] = 0x0;
    }
}

void
tct_shake_absorb (uint8_t state[TCT_KP1600_STATE_LEN], const uint8_t *chunk,
                  const enum tct_shake_level level)
    __CPROVER_requires (__CPROVER_is_fresh (state, TCT_KP1600_STATE_LEN))
        __CPROVER_requires (__CPROVER_is_fresh (chunk, (level == TCT_SHAKE128)
                                                           ? 168
                                                           : 136))
            __CPROVER_assigns (__CPROVER_object_upto (state,
                                                      TCT_KP1600_STATE_LEN))
{
  const uint8_t r = (level == TCT_SHAKE128) ? 168 : 136;
  for (uint8_t i = 0; i < r; ++i)
    __CPROVER_loop_invariant (i <= r) __CPROVER_decreases (r - i)
    {
      state[i] ^= chunk[i];
    }
  kp (state, TCT_SHAKE_ROUNDS);
}

void
tct_shake_squeeze_destructive (uint8_t state[TCT_KP1600_STATE_LEN],
                               uint8_t *output, const uint64_t output_len,
                               const enum tct_shake_level level)
    __CPROVER_requires (output_len < 0xffffffffffffffff - 168)
        __CPROVER_requires (__CPROVER_is_fresh (state, TCT_KP1600_STATE_LEN))
            __CPROVER_assigns (__CPROVER_object_upto (state,
                                                      TCT_KP1600_STATE_LEN))
                __CPROVER_requires (__CPROVER_is_fresh (output, output_len))
                    __CPROVER_assigns (__CPROVER_object_upto (output,
                                                              output_len))
{
  const uint8_t r = (level == TCT_SHAKE128) ? 168 : 136;
  for (uint64_t i = 0; i < output_len; i += r)
    __CPROVER_loop_invariant (i <= output_len + r)
        __CPROVER_decreases (output_len + r - i)
    {
      for (unsigned int j = 0; j < (output_len - i) && j < r; ++j)
        __CPROVER_loop_invariant (j <= (output_len - i) && j <= r)
            __CPROVER_decreases (r - j)
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
    __CPROVER_requires (output_len < 0xffffffffffffffff - 168)
        __CPROVER_requires (data_len < 0xffffffffffffffff - 168)
            __CPROVER_requires (__CPROVER_is_fresh (output, output_len))
                __CPROVER_requires (__CPROVER_is_fresh (data, data_len))
                    __CPROVER_assigns (__CPROVER_object_upto (output,
                                                              output_len))
{
  const uint8_t r = (level == TCT_SHAKE128) ? 168 : 136;
  uint8_t state[TCT_KP1600_STATE_LEN];
  tct_shake_init (state);
  uint8_t buf[168];
  for (uint64_t i = 0; i <= data_len; i += r)
    __CPROVER_assigns (i, __CPROVER_object_upto (buf, r),
                       __CPROVER_object_upto (state, TCT_KP1600_STATE_LEN))
        __CPROVER_loop_invariant (i <= data_len + r)
            __CPROVER_decreases (data_len + r - i)
    {
      for (uint64_t j = 0; j < r && j < data_len - i; ++j)
        __CPROVER_assigns (j, __CPROVER_object_upto (buf, r))
            __CPROVER_loop_invariant (j <= (data_len - i) && j <= r)
                __CPROVER_decreases (r - j)
        {
          buf[j] = data[i + j];
        }
      for (uint64_t j = data_len - i; j < r; ++j)
        __CPROVER_assigns (j, __CPROVER_object_upto (buf, r))
            __CPROVER_loop_invariant (data_len - i <= j && j <= r)
                __CPROVER_decreases (r - j)
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
