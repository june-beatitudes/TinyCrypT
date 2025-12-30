#include <stdbool.h>
#include <stdint.h>

#include <stdio.h>

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

static void
turboshake128_init (uint8_t *state)
{
  for (unsigned int i = 0; i < 200; ++i)
    {
      state[i] = 0x0;
    }
}

static void
turboshake128_absorb (uint8_t *state, const uint8_t *data,
                      const uint64_t data_len, const uint8_t separation_byte,
                      const bool is_last)
{
  for (uint64_t i = 0; i <= data_len; i += 168)
    {
      uint8_t buf[200];
      for (unsigned int j = 0; j < ((data_len - i < 168) ? data_len - i : 168);
           ++j)
        {
          buf[j] = data[i + j];
        }
      for (unsigned int j = ((data_len - i < 168) ? data_len - i : 168);
           j < 200; ++j)
        {
          buf[j] = 0x0;
        }
      if (data_len - i < 168 && is_last)
        {
          buf[data_len - i] = separation_byte;
          buf[167] = 0x80;
        }
      for (unsigned int j = 0; j < 200; ++j)
        {
          state[j] ^= buf[j];
        }
      kp (state);
    }
}

static void
turboshake128_squeeze (uint8_t *state, uint8_t *output,
                       const uint64_t output_len)
{
  for (uint64_t i = 0; i < output_len; i += 168)
    {
      for (unsigned int j = 0;
           j < ((output_len - i < 168) ? output_len - i : 168); ++j)
        {
          output[i + j] = state[j];
        }
      kp (state);
    }
}

static void
length_encode (const uint64_t n, uint8_t *out, uint64_t *out_len)
{
  (*out_len) = 1;
  for (uint64_t i = n; i > 0; i /= 256)
    {
      (*out_len)++;
    }
  for (uint64_t i = n; i > 0; i /= 256)
    {
      out[(*out_len) - 1 - (i / 256)] = i & 0xFF;
    }
  out[(*out_len) - 1] = ((*out_len) - 1) & 0xFF;
}

static void
tct_kangarootwelve128 (const uint8_t *input, const uint64_t input_len,
                       const uint8_t *custom_str, const uint64_t cs_len,
                       uint8_t *output, const uint64_t output_len)
{
  uint8_t buf[168];
  uint8_t state[200];
  turboshake128_init (state);
  if (input_len + cs_len + sizeof (uint64_t) <= 8192)
    {
      uint8_t encoded[8];
      uint64_t encoded_len;
      length_encode (cs_len, encoded, &encoded_len);
      const uint64_t s_size = input_len + cs_len + encoded_len;
      for (uint64_t i = 0; i < s_size; i += 168)
        {
          for (uint64_t j = 0; j < ((s_size - i < 168) ? s_size - i : 168);
               ++j)
            {
              if (i + j < input_len)
                {
                  buf[j] = input[i + j];
                }
              else if (i + j < input_len + cs_len)
                {
                  buf[j] = custom_str[i + j - input_len];
                }
              else
                {
                  buf[j] = encoded[i + j - input_len - cs_len];
                }
            }
          turboshake128_absorb (state, buf,
                                ((s_size - i < 168) ? s_size - i : 168), 0x07,
                                s_size - i < 168);
        }
      turboshake128_squeeze (state, output, output_len);
      return;
    }
}

int
main (int argc, char **argv)
{
  uint8_t output[64];
  tct_kangarootwelve128 (NULL, 0, NULL, 0, output, 64);
  for (unsigned int i = 0; i < 64; ++i)
    {
      printf ("%02x ", output[i]);
      if (i % 16 == 15)
        {
          printf ("\n");
        }
    }
  return 0;
}