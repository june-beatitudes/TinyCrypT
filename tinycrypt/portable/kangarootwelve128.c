#include <stdbool.h>
#include <stdint.h>

#include "tinycrypt/kangarootwelve128.h"

/*@ requires 1 <= c % 64 < 64;
  @ terminates \true;
  @ exits \false;
  @ assigns \nothing;
 */
static uint64_t
rotl64 (uint64_t x, uint32_t c)
{
  return (x << (c % 64)) | (x >> (64 - (c % 64)));
}

/*@ requires \valid_read(x + (0..7));
  @ terminates \true;
  @ exits \false;
  @ assigns \nothing;
 */
static uint64_t
from_le64 (const uint8_t *x)
{
  uint64_t u = 0x0;
  /*@ loop invariant 0 <= i <= 8;
    @ loop assigns i, u;
    @ loop variant 8 - i;
   */
  for (unsigned int i = 0; i < 8; ++i)
    {
      u <<= 8;
      u |= x[7 - i];
    }
  return u;
}

/*@ requires \valid(x + (0..7));
  @ terminates \true;
  @ exits \false;
  @ assigns x[0..7];
 */
static void
to_le64 (uint64_t u, uint8_t *x)
{
  /*@ loop invariant 0 <= i <= 8;
    @ loop assigns i, u, x[0..7];
    @ loop variant 8 - i;
   */
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

/*@ requires \valid(state + (0..199));
  @ terminates \true;
  @ exits \false;
  @ assigns state[0..199];
 */
static void
kp (uint8_t state[200])
{
  uint64_t lanes[5][5];
  /*@ loop invariant 0 <= x <= 5;
    @ loop assigns x, lanes[0..4][0..4];
    @ loop variant 5 - x;
   */
  for (unsigned int x = 0; x < 5; ++x)
    {
      /*@ loop invariant 0 <= y <= 5;
        @ loop assigns y, lanes[x][0..4];
        @ loop variant 5 - y;
       */
      for (unsigned int y = 0; y < 5; ++y)
        {
          lanes[x][y] = from_le64 (&state[8 * (x + 5 * y)]);
        }
    }
  /*@ loop invariant 0 <= round <= 12;
    @ loop assigns round, lanes[0..4][0..4];
    @ loop variant 12 - round;
   */
  for (unsigned int round = 0; round < 12; ++round)
    {
      uint64_t C[5];
      uint64_t D[5];
      /*@ loop invariant 0 <= x <= 5;
        @ loop assigns x, C[0..4];
        @ loop variant 5 - x;
       */
      for (unsigned int x = 0; x < 5; ++x)
        {
          C[x] = lanes[x][0];
          C[x] ^= lanes[x][1];
          C[x] ^= lanes[x][2];
          C[x] ^= lanes[x][3];
          C[x] ^= lanes[x][4];
        }
      /*@ loop invariant 0 <= x <= 5;
        @ loop assigns x, D[0..4];
        @ loop variant 5 - x;
       */
      for (unsigned int x = 0; x < 5; ++x)
        {
          D[x] = C[(x + 4) % 5] ^ rotl64 (C[(x + 1) % 5], 1);
        }
      /*@ loop invariant 0 <= y <= 5;
        @ loop assigns y, lanes[0..4][0..4];
        @ loop variant 5 - y;
       */
      for (unsigned int y = 0; y < 5; ++y)
        {
          /*@ loop invariant 0 <= x <= 5;
            @ loop assigns x, lanes[0..4][y];
            @ loop variant 5 - x;
          */
          for (unsigned int x = 0; x < 5; ++x)
            {
              lanes[x][y] ^= D[x];
            }
        }
      uint64_t x = 1;
      uint64_t y = 0;
      uint64_t current = lanes[x][y];
      /*@ loop invariant 0 <= t <= 24;
        @ loop assigns x, y, current, t, lanes[0..4][0..4];
        @ loop variant 24 - t;
       */
      for (unsigned int t = 0; t < 24; ++t)
        {
          uint64_t tmp = x;
          x = y;
          y = (2 * tmp + 3 * y) % 5;
          //@ assert 0 <= y <= 4;
          tmp = current;
          current = lanes[x][y];
          lanes[x][y] = rotl64 (tmp, (t + 1) * (t + 2) / 2);
        }
      uint64_t T[5];
      /*@ loop invariant 0 <= y <= 5;
        @ loop assigns y, T[0..4], lanes[0..4][0..4];
        @ loop variant 5 - y;
       */
      for (unsigned int y = 0; y < 5; ++y)
        {
          /*@ loop invariant 0 <= x <= 5;
            @ loop assigns x, T[0..4];
            @ loop variant 5 - x;
           */
          for (unsigned int x = 0; x < 5; ++x)
            {
              T[x] = lanes[x][y];
            }
          /*@ loop invariant 0 <= x <= 5;
            @ loop assigns x, lanes[0..4][y];
            @ loop variant 5 - x;
           */
          for (unsigned int x = 0; x < 5; ++x)
            {
              lanes[x][y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5]);
            }
        }
      lanes[0][0] ^= RC[round];
    }
  uint64_t cursor = 0;
  /*@ loop invariant 0 <= y <= 5;
    @ loop invariant 0 <= cursor <= 200;
    @ loop assigns cursor, y, state[0..199];
    @ loop variant 5 - y;
   */
  for (unsigned int y = 0; y < 5; ++y)
    {
      /*@ loop invariant 0 <= x <= 5;
        @ loop invariant 40*y <= cursor <= 40*y + 40;
        @ loop assigns cursor, x, state[40*y..40*y+39];
        @ loop variant 5 - x;
       */
      for (unsigned int x = 0; x < 5; ++x)
        {
          to_le64 (lanes[x][y], state + cursor);
          cursor += 8;
        }
    }
}

/*@ requires \valid(state + (0..199));
  @ terminates \true;
  @ exits \false;
  @ assigns state[0..199];
 */
void
tct_turboshake128_init (uint8_t state[TCT_TURBOSHAKE128_STATE_LEN])
{
  /*@ loop invariant 0 <= i <= 200;
    @ loop assigns i, state[0..199];
    @ loop variant 200 - i;
   */
  for (unsigned int i = 0; i < TCT_TURBOSHAKE128_STATE_LEN; ++i)
    {
      state[i] = 0x0;
    }
}

/*@ requires \valid(state + (0..199));
  @ requires \valid(data + (0..data_len-1));
  @ requires \separated(state, data);
  @ requires data_len < 200;
  @ terminates \true;
  @ exits \false;
  @ assigns state[0..199];
 */
void
tct_turboshake128_absorb (uint8_t state[TCT_TURBOSHAKE128_STATE_LEN],
                          const uint8_t *data, const uint64_t data_len,
                          const uint8_t separation_byte)
{
  /*@ loop invariant 0 <= i <= data_len;
    @ loop assigns i, state[0..data_len-1];
    @ loop variant data_len - i;
   */
  for (uint64_t i = 0; i < data_len; ++i)
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

/*@ requires \valid(state + (0..199));
  @ requires \valid(output + (0..output_len-1));
  @ requires \separated(state + (0..199), output + (0..output_len-1));
  @ requires 0 <= output_len <= 0xffffffffffffffff - 168;
  @ terminates \true;
  @ exits \false;
  @ assigns state[0..199], output[0..output_len-1];
 */
void
tct_turboshake128_squeeze_destructive (
    uint8_t state[TCT_TURBOSHAKE128_STATE_LEN], uint8_t *output,
    const uint64_t output_len)
{
  /*@ loop invariant 0 <= i <= output_len + 168;
    @ loop assigns i, output[0..output_len-1], state[0..199];
    @ loop variant output_len + 168 - i;
   */
  for (uint64_t i = 0; i < output_len; i += 168)
    {
      /*@ loop invariant output_len - i < 168 ==> 0<= j <= output_len - i;
        @ loop invariant output_len - i >= 168 ==> 0 <= j <= 168;
        @ loop assigns j;
        @ loop assigns output[i..((output_len - i < 168) ? output_len-1 :
            i+167)];
        @ loop variant 168 - j;
       */
      for (unsigned int j = 0;
           j < ((output_len - i < 168) ? output_len - i : 168); ++j)
        {
          output[i + j] = state[j];
        }
      kp (state);
    }
}

/*@ requires \valid(out + (0..7));
  @ requires \valid(out_len);
  @ terminates \true;
  @ exits \false;
  @ ensures 1 <= *out_len <= 8;
  @ assigns *out_len;
  @ assigns out[0..7];
 */
static void
length_encode (const uint64_t n, uint8_t *out, uint64_t *out_len)
{
  (*out_len) = 1;
  /*@ loop invariant 0 <= i <= n;
    @ loop assigns *out_len, i;
    @ loop variant n - i;
   */
  for (uint64_t i = n; i > 0; i /= 256)
    {
      (*out_len)++;
    }
  /*@ loop invariant 0 <= i <= 7;
    @ loop assigns out[1..7];
    @ loop variant 7 - i;
   */
  for (uint64_t i = 0; i < (*out_len) - 1; ++i)
    {
      out[(*out_len) - 2 - i] = (n >> (8 * i)) & 0xFF;
    }
  out[(*out_len) - 1] = ((*out_len) - 1) & 0xFF;
}

/*@ requires \valid_read(input + (0..input_len-1));
  @ requires \valid_read(custom_str + (0..cs_len-1));
  @ requires \valid(output + (0..output_len-1));
  @ requires \separated(output + (0..output_len-1), custom_str +
      (0..cs_len-1));
  @ requires 0 <= output_len + cs_len <= 18446744073709551439;
  @ requires \separated(output + (0..output_len-1), input + (0..input_len-1));
  @ terminates \true;
  @ exits \false;
  @ assigns output[0..output_len-1];
 */
void
tct_kangarootwelve128 (const uint8_t *input, const uint64_t input_len,
                       const uint8_t *custom_str, const uint64_t cs_len,
                       uint8_t *output, const uint64_t output_len)
{
  uint8_t buf[168];
  uint8_t state[TCT_TURBOSHAKE128_STATE_LEN];
  tct_turboshake128_init (state);
  uint8_t encoded[8];
  uint64_t encoded_len;
  length_encode (cs_len, encoded, &encoded_len);
  const uint64_t s_size = input_len + cs_len + encoded_len;
  if (s_size <= 8192)
    {
      /*@ loop invariant 0 <= i <= s_size + 168;
        @ loop assigns i, buf[0..((s_size - i < 168) ? s_size - i - 1 : 167)];
        @ loop assigns state[0..199];
        @ loop variant s_size + 168 - i;
       */
      for (uint64_t i = 0; i < s_size; i += 168)
        {
          uint64_t buf_len = (s_size - i < 168) ? s_size - i : 168;
          /*@ loop invariant 0 <= j <= buf_len;
            @ loop assigns j, buf[0..buf_len-1];
            @ loop variant buf_len - j;
           */
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
          tct_turboshake128_absorb (state, buf, buf_len, 0x07);
        }
      tct_turboshake128_squeeze_destructive (state, output, output_len);
      return;
    }
  uint64_t buf_len;
  /*@ loop invariant 0 <= i <= 8368;
    @ loop assigns i, state[0..199], buf[0..167];
    @ loop variant 8368 - i;
   */
  for (unsigned int i = 0; i < 8200; i += 168)
    {
      buf_len = (8200 - i < 168) ? 8200 - i : 168;
      /*@ loop invariant 0 <= j <= buf_len;
        @ loop assigns j, buf[0..buf_len-1];
        @ loop variant buf_len - j;
       */
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
          tct_turboshake128_absorb (state, buf, 168, 0x06);
        }
    }
  uint64_t offset = 8192;
  uint64_t num_block = 0;
  /*@ loop invariant 8192 <= offset <= s_size + 8192;
    @ loop assigns offset, num_block, state[0..199], buf_len;
    @ loop variant s_size - offset;
   */
  while (offset < s_size)
    {
      uint64_t block_size = (8192 < s_size - offset) ? 8192 : s_size - offset;
      uint8_t cv[32];
      uint8_t cv_buf[168];
      uint8_t cv_state[200];
      tct_turboshake128_init (cv_state);
      /*@ loop invariant offset <= i <= offset + block_size + 168;
        @ loop assigns i, cv_buf[0..167], cv_state[0..199];
        @ loop variant offset + block_size + 168 - i;
       */
      for (uint64_t i = offset; i < offset + block_size; i += 168)
        {
          uint64_t cv_block_size = (168 < offset + block_size - i)
                                       ? 168
                                       : offset + block_size - i;
          /*@ loop invariant 0 <= j <= cv_block_size;
            @ loop assigns j, cv_buf[0..cv_block_size-1];
            @ loop variant cv_block_size - j;
           */
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
          tct_turboshake128_absorb (cv_state, cv_buf, cv_block_size, 0x0B);
        }
      tct_turboshake128_squeeze_destructive (cv_state, cv, 32);
      if (buf_len + 32 >= 168)
        {
          /*@ loop invariant buf_len <= i <= 168;
            @ loop assigns i, buf[buf_len..167];
            @ loop variant 168 - i;
           */
          for (unsigned int i = buf_len; i < 168; ++i)
            {
              buf[i] = cv[i - buf_len];
            }
          tct_turboshake128_absorb (state, buf, 168, 0x06);
          /*@ loop invariant (buf_len + 32) - 168 <= i <= 32;
            @ loop assigns i, buf[(buf_len+32-168)..31];
            @ loop variant 32 - i;
           */
          for (unsigned int i = (buf_len + 32) - 168; i < 32; ++i)
            {
              buf[i] = cv[i];
            }
        }
      else
        {
          /*@ loop invariant buf_len <= i <= buf_len + 32;
            @ loop assigns i, buf[buf_len..buf_len+31];
            @ loop variant buf_len + 32 - i;
           */
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
      tct_turboshake128_absorb (state, buf, 168, 0x06);

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
  tct_turboshake128_absorb (state, buf, buf_len, 0x06);
  tct_turboshake128_squeeze_destructive (state, output, output_len);
}
