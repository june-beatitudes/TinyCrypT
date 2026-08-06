import sys

with open(sys.argv[1], "r") as test_spec, open(sys.argv[2], "w") as output_file:
    vecno = 0
    print("#include <stdint.h>", file=output_file)
    print('#include "unity.h"', file=output_file)
    print('#include "tinycrypt/ed25519.h"', file=output_file)
    for line in test_spec:
        if line.startswith("SK"):
            print(
                f"static const uint8_t SK{vecno}[] = "
                + "{0x"
                + ",0x".join(
                    [line[5:-1][i : i + 2] for i in range(0, len(line) - 6, 2)]
                )
                + ",};",
                file=output_file,
            )
        elif line.startswith("PK"):
            print(
                f"static const uint8_t PK{vecno}[] = "
                + "{0x"
                + ",0x".join(
                    [line[5:-1][i : i + 2] for i in range(0, len(line) - 6, 2)]
                )
                + ",};",
                file=output_file,
            )
        elif line.startswith("MSG"):
            if len(line) > 5:
                print(
                    f"static const uint8_t MSG{vecno}[] = "
                    + "{0x"
                    + ",0x".join(
                        [line[5:-1][i : i + 2] for i in range(0, len(line) - 6, 2)]
                    )
                    + ",};",
                    file=output_file,
                )
            else:
                print(
                    f"static const uint8_t MSG{vecno}[0]" + " = {};", file=output_file
                )
        elif line.startswith("SIG"):
            print(
                f"static const uint8_t SIG{vecno}[] = "
                + "{0x"
                + ",0x".join(
                    [line[5:-1][i : i + 2] for i in range(0, len(line) - 6, 2)]
                )
                + ",};",
                file=output_file,
            )
            vecno += 1

    for i in range(vecno):
        print(f"void test_ed25519_keygen{i} (void)", file=output_file)
        print("{", file=output_file)
        print("uint8_t actual_pk[32];", file=output_file)
        print(f"tct_ed25519_keygen(SK{i}, actual_pk);", file=output_file)
        print(f"TEST_ASSERT_EQUAL_HEX8_ARRAY(PK{i}, actual_pk, 32);", file=output_file)
        print("}", file=output_file)

        print(f"void test_ed25519_sign{i} (void)", file=output_file)
        print("{", file=output_file)
        print("uint8_t actual_signature[64];", file=output_file)
        print(f"uint8_t working_buf[sizeof(MSG{i}) + 64];", file=output_file)
        print(
            f"tct_ed25519_sign (MSG{i}, sizeof(MSG{i}), SK{i}, PK{i}, working_buf, actual_signature);",
            file=output_file,
        )
        print(
            f"TEST_ASSERT_EQUAL_HEX8_ARRAY(SIG{i}, actual_signature, 64);",
            file=output_file,
        )
        print("}", file=output_file)

        print(f"void test_ed25519_verify{i}_happy (void)", file=output_file)
        print("{", file=output_file)
        print(f"uint8_t working_buf[sizeof(MSG{i}) + 64];", file=output_file)
        print(
            f"TEST_ASSERT_TRUE(tct_ed25519_verify(PK{i}, MSG{i}, sizeof(MSG{i}), working_buf, SIG{i}));",
            file=output_file,
        )
        print("}", file=output_file)

        print(f"void test_ed25519_verify{i}_sad (void)", file=output_file)
        print("{", file=output_file)
        print(f"uint8_t working_buf[sizeof(MSG{i}) + 64];", file=output_file)
        print("uint8_t tampered[64];", file=output_file)
        print("for (size_t i = 0; i < 64; ++i)", file=output_file)
        print("{", file=output_file)
        print(f"tampered[i] = SIG{i}[i];", file=output_file)
        print("}", file=output_file)
        print(f"tampered[{i} % 64] ^= 0b10101010;", file=output_file)
        print(
            f"TEST_ASSERT_FALSE(tct_ed25519_verify(PK{i}, MSG{i}, sizeof(MSG{i}), working_buf, tampered));",
            file=output_file,
        )
        print("}", file=output_file)
