import os
import sys

import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
import cryptography.hazmat.primitives.asymmetric.x25519 as x25519
import cryptography.hazmat.primitives.ciphers.aead as aead

N_FUZZ_TESTS = 1000

with open(sys.argv[1], "w") as of:
    print("#include <stdint.h>", file=of)
    print('#include "unity.h"', file=of)
    print('#include "tinycrypt/chacha20_poly1305.h"', file=of)
    print('#include "tinycrypt/x25519.h"', file=of)
    print('#include "tinycrypt/ed25519.h"', file=of)

    for i in range(N_FUZZ_TESTS):
        aad = os.urandom(int.from_bytes(os.urandom(1)))
        data = os.urandom(int.from_bytes(os.urandom(2)) % 1024)
        nonce = os.urandom(12)
        key = aead.ChaCha20Poly1305.generate_key()
        cc20_inst = aead.ChaCha20Poly1305(key)
        ct = cc20_inst.encrypt(nonce, data, aad)
        print(f"void test_cc20p1305_fuzz{i} (void)", file=of)
        print("{", file=of)
        print(
            "const uint8_t AAD[] = {"
            + ", ".join([f"0x{int(b):x}" for b in aad])
            + "};",
            file=of,
        )
        print(
            "const uint8_t DATA[] = {"
            + ", ".join([f"0x{int(b):x}" for b in data])
            + "};",
            file=of,
        )
        print(
            "const uint8_t NONCE[12] = {"
            + ", ".join([f"0x{int(b):x}" for b in nonce])
            + "};",
            file=of,
        )
        print(
            "const uint8_t KEY[32] = {"
            + ", ".join([f"0x{int(b):x}" for b in key])
            + "};",
            file=of,
        )
        print(
            "const uint8_t EXPECTED[] = {"
            + ", ".join([f"0x{int(b):x}" for b in ct])
            + "};",
            file=of,
        )
        print("uint8_t actual[sizeof (EXPECTED)];", file=of)
        print(
            "tct_aead_chacha20_poly1305_encrypt (AAD, sizeof (AAD), KEY,NONCE, DATA, sizeof (DATA), actual, actual + sizeof (DATA));",
            file=of,
        )
        print(
            "tct_aead_chacha20_poly1305_encrypt (AAD, sizeof (AAD), KEY,NONCE, DATA, sizeof (DATA), actual, actual + sizeof (DATA));",
            file=of,
        )
        print(
            "TEST_ASSERT_EQUAL_HEX8_ARRAY (EXPECTED, actual, sizeof (EXPECTED));",
            file=of,
        )
        print("}", file=of)

        ed25519_sk = os.urandom(32)
        ed25519_pk = (
            ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_sk).public_key().public_bytes_raw()
        )
        data = os.urandom(int.from_bytes(os.urandom(2)) % 1024)
        signature = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_sk).sign(data)
        print(f"void test_ed25519_fuzz{i} (void)", file=of)
        print("{", file=of)
        print(
            "const uint8_t SK[32] = {"
            + ", ".join([f"0x{int(b):x}" for b in ed25519_sk])
            + "};",
            file=of,
        )
        print(
            "const uint8_t PK[32] = {"
            + ", ".join([f"0x{int(b):x}" for b in ed25519_pk])
            + "};",
            file=of,
        )
        print(
            "const uint8_t DATA[] = {"
            + ", ".join([f"0x{int(b):x}" for b in data])
            + "};",
            file=of,
        )
        print(
            "const uint8_t EXPECTED[64] = {"
            + ", ".join([f"0x{int(b):x}" for b in signature])
            + "};",
            file=of,
        )
        print("uint8_t actual[64];", file=of)
        print("uint8_t working_buf[sizeof (DATA) + 64];", file=of)
        print(
            "tct_ed25519_sign (DATA, sizeof (DATA), SK, PK, working_buf, actual);",
            file=of,
        )
        print(
            "TEST_ASSERT_EQUAL_HEX8_ARRAY (EXPECTED, actual, 64);",
            file=of,
        )
        print("}", file=of)

        curve25519_sk = os.urandom(32)
        curve25519_pk = (
            x25519.X25519PrivateKey.generate().public_key().public_bytes_raw()
        )
        expected = x25519.X25519PrivateKey.from_private_bytes(curve25519_sk).exchange(
            x25519.X25519PublicKey.from_public_bytes(curve25519_pk)
        )
        print(f"void test_x25519_fuzz{i} (void)", file=of)
        print("{", file=of)
        print(
            "const uint8_t SK[32] = {"
            + ", ".join([f"0x{int(b):x}" for b in curve25519_sk])
            + "};",
            file=of,
        )
        print(
            "const uint8_t PK[32] = {"
            + ", ".join([f"0x{int(b):x}" for b in curve25519_pk])
            + "};",
            file=of,
        )
        print(
            "const uint8_t EXPECTED[32] = {"
            + ", ".join([f"0x{int(b):x}" for b in expected])
            + "};",
            file=of,
        )
        print("uint8_t actual[32];", file=of)
        print("tct_x25519 (SK, PK, actual);", file=of)
        print(
            "TEST_ASSERT_EQUAL_HEX8_ARRAY (EXPECTED, actual, 32);",
            file=of,
        )
        print("}", file=of)
