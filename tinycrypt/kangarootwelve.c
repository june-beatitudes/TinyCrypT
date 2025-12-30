#include <stdbool.h>
#include <stdint.h>

static uint64_t
rotl64 (uint64_t x, int c)
{
  return (x << c) | ((x & 0xffffffffffffffff) >> (64 - c));
}

static uint64_t
from_le64 (const uint8_t *x)
{
  uint64_t u = 0x0;
  for (unsigned int i = 0; i < 8; ++i)
    {
      u <<= 8;
      u |= x[7 - i];
    }
  return u;
}

static void
to_le64 (uint64_t u, uint8_t *x)
{
  for (unsigned int i = 0; i < 8; ++i)
    {
      x[i] = u & 0xFF;
      u >>= 8;
    }
}

static const uint64_t RC[12] = {
  0x8000808B,
  0x800000000000008B,
  0x8000000000008089,
  0x8000000000008003,
  0x8000000000008002,
  0x8000000000000080,
  0x800A,
  0x800000008000000A,
  0x8000000080008081,
  0x8000000000008080,
  0x0000000080000001,
  0x8000000080008008,
};

static void
kp (uint8_t state[200])
{
  uint64_t lanes[5][5];
  for (unsigned int x = 0; x < 5; ++x)
    {
      for (unsigned int y = 0; y < 5; ++y)
        {
          lanes[x][y] = from_le64 (&state[8 * (x + 5 * y)]);
        }
    }
  for (unsigned int round = 0; round < 12; ++round)
    {
      uint64_t C[5];
      uint64_t D[5];
      for (unsigned int x = 0; x < 5; ++x)
        {
          C[x] = lanes[x][0];
          C[x] ^= lanes[x][1];
          C[x] ^= lanes[x][2];
          C[x] ^= lanes[x][3];
          C[x] ^= lanes[x][4];
        }
      for (unsigned int x = 0; x < 5; ++x)
        {
          D[x] = C[(x + 4) % 5] ^ rotl64 (C[(x + 1) % 5], 1);
        }
      for (unsigned int y = 0; y < 5; ++y)
        {
          for (unsigned int x = 0; x < 5; ++x)
            {
              lanes[x][y] ^= D[x];
            }
        }
      uint64_t x = 1;
      uint64_t y = 0;
      uint64_t current = lanes[x][y];
      for (unsigned int t = 0; t < 24; ++t)
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
        {
          for (unsigned int x = 0; x < 5; ++x)
            {
              T[x] = lanes[x][y];
            }
          for (unsigned int x = 0; x < 5; ++x)
            {
              lanes[x][y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5]);
            }
        }
      lanes[0][0] ^= RC[round];
    }
  unsigned int cursor = 0;
  for (unsigned int y = 0; y < 5; ++y)
    {
      for (unsigned int x = 0; x < 5; ++x)
        {
          to_le64 (lanes[x][y], state + cursor);
          cursor += 8;
        }
    }
}