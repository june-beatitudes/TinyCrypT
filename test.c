#include <stdint.h>
#include <stdio.h>

static void
add_shifted (uint32_t *h, const uint32_t *c, uint8_t shift)
{
  uint32_t shifted[16];
  for (uint8_t i = 0; i < 16; ++i)
    {
      shifted[i] = 0x0;
    }
  shifted[shift / 32] = (c[0] << (shift % 32)) & 0xffffffff;
  for (uint8_t i = shift / 32 + 1; i < shift / 32 + 9 && i < 16; ++i)
    {
      if (shift % 32 == 0)
        {
          shifted[i] = c[i - shift / 32];
        }
      else
        {
          shifted[i] = (c[i - shift / 32 - 1] >> (32 - (shift % 32)))
                       | ((c[i - shift / 32] << (shift % 32)) & 0xffffffff);
        }
    }
  if (shift / 32 + 9 < 16)
    {
      shifted[shift / 32 + 9] = c[8] >> (32 - (shift % 32));
    }
  uint64_t acc = 0;
  for (unsigned int i = 0; i < 16; ++i)
    {
      acc += (uint64_t)h[i] + (uint64_t)shifted[i];
      h[i] = acc & 0xffffffff;
      acc >>= 32;
    }
}

int
main ()
{
  uint32_t buf[16] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint32_t to_add[9] = {
    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  for (uint16_t i = 0; i <= 255; ++i)
    {
      add_shifted (buf, to_add, i);
      for (unsigned int i = 0; i < 16; ++i)
        {
          printf ("%08x", buf[15 - i]);
        }
      printf ("\n");
    }
  return 0;
}