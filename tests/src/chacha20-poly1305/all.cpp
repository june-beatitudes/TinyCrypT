extern "C"
{
#include "tinycrypt/chacha20_poly1305.h"
}
#include "gtest/gtest.h"
#include <valgrind/memcheck.h>
#include <cstdint>
#include <cstring>
#include <vector>

TEST (ChaCha20_Poly1305, cc20_p1305_full)
{
  const uint8_t KEY[]
      = { 0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31, 0xf3, 0x14, 0xaf,
          0x57, 0xf3, 0xbe, 0x3b, 0x50, 0x06, 0xda, 0x37, 0x1e, 0xce, 0x27,
          0x2a, 0xfa, 0x1b, 0x5d, 0xbd, 0xd1, 0x10, 0x0a, 0x10, 0x07 };
  const uint8_t INPUT[]
      = { 0x86, 0xd0, 0x99, 0x74, 0x84, 0x0b, 0xde, 0xd2, 0xa5, 0xca };
  const uint8_t NONCE[] = { 0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a };
  const uint8_t AAD[]
      = { 0x87, 0xe2, 0x29, 0xd4, 0x50, 0x08, 0x45, 0xa0, 0x79, 0xc0 };
  const uint8_t EXPECTED_OUTPUT[]
      = { 0xe3, 0xe4, 0x46, 0xf7, 0xed, 0xe9, 0xa1, 0x9b, 0x62,
          0xa4, 0x67, 0x7d, 0xab, 0xf4, 0xe3, 0xd2, 0x4b, 0x87,
          0x6b, 0xb2, 0x84, 0x75, 0x38, 0x96, 0xe1, 0xd6 };
  uint8_t actual_output[sizeof (EXPECTED_OUTPUT)];
  VALGRIND_MAKE_MEM_UNDEFINED(KEY, sizeof(KEY));
  tct_aead_chacha20_poly1305_encrypt (AAD, sizeof (AAD), KEY, NONCE, INPUT,
                                      sizeof (INPUT), actual_output,
                                      actual_output + sizeof (INPUT));
  VALGRIND_MAKE_MEM_DEFINED(actual_output, sizeof(actual_output));
  EXPECT_EQ (memcmp (actual_output, EXPECTED_OUTPUT, sizeof (EXPECTED_OUTPUT)),
             0);
}

TEST (ChaCha20_Poly1305, round_trip_lengths)
{
  const uint8_t KEY[32]
      = { 0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31, 0xf3, 0x14, 0xaf,
          0x57, 0xf3, 0xbe, 0x3b, 0x50, 0x06, 0xda, 0x37, 0x1e, 0xce, 0x27,
          0x2a, 0xfa, 0x1b, 0x5d, 0xbd, 0xd1, 0x10, 0x0a, 0x10, 0x07 };
  const uint8_t NONCE[8] = { 0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a };
  const uint8_t AAD[10]
      = { 0x87, 0xe2, 0x29, 0xd4, 0x50, 0x08, 0x45, 0xa0, 0x79, 0xc0 };
  VALGRIND_MAKE_MEM_UNDEFINED(KEY, sizeof(KEY));

  // Lengths straddling block (64) and vector-width (256, 512) boundaries.
  const size_t lengths[] = { 0,   1,   63,  64,  65,  127, 128,  255,  256,
                             257, 320, 511, 512, 513, 576, 1024, 2048, 4096 };

  for (size_t aad_len = 0; aad_len <= sizeof (AAD); aad_len += sizeof (AAD))
    {
      for (size_t len : lengths)
        {
          std::vector<uint8_t> plaintext (len), cipher (len), recovered (len);
          for (size_t i = 0; i < len; ++i)
            plaintext[i] = static_cast<uint8_t> (i * 31 + 7);

          uint8_t mac[16];
          tct_aead_chacha20_poly1305_encrypt (AAD, aad_len, KEY, NONCE,
                                              plaintext.data (), len,
                                              cipher.data (), mac);

          // ciphertext must differ from plaintext where there is data
          if (len > 0)
            {
              EXPECT_NE (memcmp (cipher.data (), plaintext.data (), len), 0)
                  << "len=" << len;
            }

          // frame = ciphertext || 16-byte tag
          std::vector<uint8_t> frame (len + 16);
          if (len != 0)
            {
              memcpy (frame.data (), cipher.data (), len);
            }
          memcpy (frame.data () + len, mac, 16);

          bool ok = tct_aead_chacha20_poly1305_decrypt_and_verify (
              AAD, aad_len, KEY, NONCE, frame.data (), len, recovered.data ());
          EXPECT_TRUE (ok) << "verify failed: aad_len=" << aad_len
                           << " len=" << len;
          if (len != 0)
            {
              EXPECT_EQ (memcmp (recovered.data (), plaintext.data (), len), 0)
                  << "aad_len=" << aad_len << " len=" << len;
            }

          // a single flipped ciphertext bit must fail verification
          if (len > 0)
            {
              frame[0] ^= 0x01;
              EXPECT_FALSE (tct_aead_chacha20_poly1305_decrypt_and_verify (
                  AAD, aad_len, KEY, NONCE, frame.data (), len,
                  recovered.data ()))
                  << "tamper not detected: len=" << len;
            }
        }
    }
}
