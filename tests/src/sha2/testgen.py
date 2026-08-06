import sys

BASE_PATH = "/".join(sys.argv[1].split("/")[:-1]) + "/"

with open(sys.argv[2], "w") as of:
    print("#include <stdint.h>", file=of)
    print('#include "unity.h"', file=of)
    print('#include "tinycrypt/sha2.h"', file=of)

    for test_group in [
        "SHA512LongMsg",
        "SHA512ShortMsg",
        "SHA256LongMsg",
        "SHA256ShortMsg",
    ]:
        vecno = 0
        with open(BASE_PATH + test_group + ".rsp") as f:
            cur_len = 0
            for line in f:
                if line.startswith("Len"):
                    cur_len = int(line[6:-1])
                elif line.startswith("Msg"):
                    if cur_len == 0:
                        print(f"static uint8_t {test_group}_MSG{vecno}[0];", file=of)
                    else:
                        print(
                            f"static uint8_t {test_group}_MSG{vecno}[] = "
                            + "{0x"
                            + ",0x".join(
                                [
                                    line[6:-1][i : i + 2]
                                    for i in range(0, len(line) - 7, 2)
                                ]
                            )
                            + ",};",
                            file=of,
                        )
                elif line.startswith("MD"):
                    print(
                        f"static uint8_t {test_group}_DIGEST{vecno}[] = "
                        + "{0x"
                        + ",0x".join(
                            [line[5:-1][i : i + 2] for i in range(0, len(line) - 6, 2)]
                        )
                        + ",};",
                        file=of,
                    )
                    vecno += 1
        for i in range(vecno):
            print(f"void test_{test_group}{i} (void)", file=of)
            print("{", file=of)
            if "512" in test_group:
                print("uint8_t actual_digest[64];", file=of)
                print(
                    f"tct_sha512({test_group}_MSG{i}, sizeof({test_group}_MSG{i}), actual_digest);",
                    file=of,
                )
                print(
                    f"TEST_ASSERT_EQUAL_HEX8_ARRAY({test_group}_DIGEST{i}, actual_digest, 64);",
                    file=of,
                )
            else:
                print("uint8_t actual_digest[32];", file=of)
                print(
                    f"tct_sha256({test_group}_MSG{i}, sizeof({test_group}_MSG{i}), actual_digest);",
                    file=of,
                )
                print(
                    f"TEST_ASSERT_EQUAL_HEX8_ARRAY({test_group}_DIGEST{i}, actual_digest, 32);",
                    file=of,
                )
            print("}", file=of)

    for test_group in ["SHA512Monte", "SHA256Monte"]:
        vecno = 0
        with open(BASE_PATH + test_group + ".rsp") as f:
            for line in f:
                if line.startswith("Seed"):
                    print(
                        f"static uint8_t {test_group}_SEED[] = "
                        + "{0x"
                        + ",0x".join(
                            [line[7:-1][i : i + 2] for i in range(0, len(line) - 8, 2)]
                        )
                        + ",};",
                        file=of,
                    )
                elif line.startswith("MD"):
                    print(
                        f"static uint8_t {test_group}_ROUND{vecno}[] = "
                        + "{0x"
                        + ",0x".join(
                            [line[5:-1][i : i + 2] for i in range(0, len(line) - 6, 2)]
                        )
                        + ",};",
                        file=of,
                    )
                    vecno += 1

        for i in range(vecno):
            print(f"void test_{test_group}{i} (void)", file=of)
            print("{", file=of)
            if "512" in test_group:
                print("uint8_t msg[192];", file=of)
                print("uint8_t digest[64];", file=of)
                print(
                    "uint8_t *a = msg; uint8_t *b = msg + 64; uint8_t *c = msg + 128;",
                    file=of,
                )
                print(
                    f"for (uint64_t j = 0; j < 64; ++j) a[j] = b[j] = c[j] = {test_group}_SEED[j];",
                    file=of,
                )
                print(f"for (uint64_t i = 0; i < ({i} + 1) * 1000; ++i)", file=of)
                print("{", file=of)
                print("if (i % 1000 == 0 && i != 0) {", file=of)
                print(
                    "for (uint64_t j = 0; j < 64; ++j) a[j] = b[j] = c[j] = digest[j];",
                    file=of,
                )
                print("}", file=of)
                print("tct_sha512(msg, sizeof(msg), digest);", file=of)
                print(
                    "for (uint64_t j = 0; j < 64; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }",
                    file=of,
                )
                print("}", file=of)
                print(
                    f"TEST_ASSERT_EQUAL_HEX8_ARRAY({test_group}_ROUND{i}, digest, 64);",
                    file=of,
                )
            else:
                print("uint8_t msg[96];", file=of)
                print("uint8_t digest[32];", file=of)
                print(
                    "uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;",
                    file=of,
                )
                print(
                    f"for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = {test_group}_SEED[j];",
                    file=of,
                )
                print(f"for (uint64_t i = 0; i < ({i} + 1) * 1000; ++i)", file=of)
                print("{", file=of)
                print("if (i % 1000 == 0 && i != 0) {", file=of)
                print(
                    "for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];",
                    file=of,
                )
                print("}", file=of)
                print("tct_sha256(msg, sizeof(msg), digest);", file=of)
                print(
                    "for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }",
                    file=of,
                )
                print("}", file=of)
                print(
                    f"TEST_ASSERT_EQUAL_HEX8_ARRAY({test_group}_ROUND{i}, digest, 32);",
                    file=of,
                )
            print("}", file=of)
