#include <stdbool.h>
#include <stdint.h>

#include "tinycrypt/kangarootwelve128.h"

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
                      const uint64_t data_len, const uint8_t separation_byte)
{
  for (unsigned int i = 0; i < data_len; ++i)
    {
      state[i] ^= data[i];
    }
  if (data_len < 168)
    {
      state[data_len] ^= separation_byte;
      state[167] ^= 0x80;
    }
  kp (state);
}

static void
turboshake128_squeeze_destructive (uint8_t *state, uint8_t *output,
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
  for (uint64_t i = 0; i < (*out_len) - 1; ++i)
    {
      out[(*out_len) - 2 - i] = (n >> (8 * i)) & 0xFF;
    }
  out[(*out_len) - 1] = ((*out_len) - 1) & 0xFF;
}

void
tct_kangarootwelve128 (const uint8_t *input, const uint64_t input_len,
                       const uint8_t *custom_str, const uint64_t cs_len,
                       uint8_t *output, const uint64_t output_len)
{
  uint8_t buf[168];
  uint8_t state[200];
  turboshake128_init (state);
  uint8_t encoded[8];
  uint64_t encoded_len;
  length_encode (cs_len, encoded, &encoded_len);
  const uint64_t s_size = input_len + cs_len + encoded_len;
  if (s_size <= 8192)
    {
      for (uint64_t i = 0; i < s_size; i += 168)
        {
          uint64_t buf_len = (s_size - i < 168) ? s_size - i : 168;
          for (uint64_t j = 0; j < buf_len; ++j)
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
          turboshake128_absorb (state, buf, buf_len, 0x07);
        }
      turboshake128_squeeze_destructive (state, output, output_len);
      return;
    }
  uint64_t buf_len;
  for (unsigned int i = 0; i < 8200; i += 168)
    {
      buf_len = (8200 - i < 168) ? 8200 - i : 168;
      for (unsigned int j = 0; j < buf_len; ++j)
        {
          if (i + j < 8192)
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
          else if (i + j < 8193)
            {
              buf[j] = 0x03;
            }
          else
            {
              buf[j] = 0x0;
            }
        }
      if (buf_len == 168)
        {
          turboshake128_absorb (state, buf, 168, 0x06);
        }
    }
  uint64_t offset = 8192;
  uint64_t num_block = 0;
  while (offset < s_size)
    {
      uint64_t block_size = (8192 < s_size - offset) ? 8192 : s_size - offset;
      uint8_t cv[32];
      uint8_t cv_buf[168];
      uint8_t cv_state[200];
      turboshake128_init (cv_state);
      for (uint64_t i = offset; i < offset + block_size; i += 168)
        {
          uint64_t cv_block_size = (168 < offset + block_size - i)
                                       ? 168
                                       : offset + block_size - i;
          for (uint64_t j = 0; j < cv_block_size; ++j)
            {
              if (i + j < input_len)
                {
                  cv_buf[j] = input[i + j];
                }
              else if (i + j < input_len + cs_len)
                {
                  cv_buf[j] = custom_str[i + j - input_len];
                }
              else
                {
                  cv_buf[j] = encoded[i + j - input_len - cs_len];
                }
            }
          turboshake128_absorb (cv_state, cv_buf, cv_block_size, 0x0B);
        }
      turboshake128_squeeze_destructive (cv_state, cv, 32);
      if (buf_len + 32 >= 168)
        {
          for (unsigned int i = buf_len; i < 168; ++i)
            {
              buf[i] = cv[i - buf_len];
            }
          turboshake128_absorb (state, buf, 168, 0x06);
          for (unsigned int i = (buf_len + 32) - 168; i < 32; ++i)
            {
              buf[i] = cv[i];
            }
        }
      else
        {
          for (unsigned int i = buf_len; i < buf_len + 32; ++i)
            {
              buf[i] = cv[i - buf_len];
            }
        }
      buf_len += 32;
      buf_len %= 168;
      num_block++;
      offset += block_size;
    }
  uint8_t nb_encoded[8];
  uint64_t nb_encoded_size;
  length_encode (num_block, nb_encoded, &nb_encoded_size);
  if (buf_len + nb_encoded_size + 2 >= 168)
    {
      for (unsigned int i = buf_len; i < 168; ++i)
        {
          if (i - buf_len < nb_encoded_size)
            {
              buf[i] = nb_encoded[i - buf_len];
            }
          else
            {
              buf[i] = 0xFF;
            }
        }
      turboshake128_absorb (state, buf, 168, 0x06);

      for (unsigned int i = (buf_len + nb_encoded_size + 2) - 168;
           i < nb_encoded_size + 2; ++i)
        {
          if (i < nb_encoded_size)
            {
              buf[i] = nb_encoded[i];
            }
          else
            {
              buf[i] = 0xFF;
            }
        }
      buf_len = (buf_len + nb_encoded_size + 2) - 168;
    }
  else
    {
      for (unsigned int i = buf_len; i < buf_len + nb_encoded_size + 2; ++i)
        {
          if (i - buf_len < nb_encoded_size)
            {
              buf[i] = nb_encoded[i - buf_len];
            }
          else
            {
              buf[i] = 0xFF;
            }
        }
      buf_len += nb_encoded_size + 2;
    }
  turboshake128_absorb (state, buf, buf_len, 0x06);
  turboshake128_squeeze_destructive (state, output, output_len);
}