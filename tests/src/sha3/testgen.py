import sys

BASE_PATH = "/".join(sys.argv[1].split("/")[:-1]) + "/"

with open(sys.argv[2], "w") as of:
    print("#include <stdint.h>", file=of)
    print('#include "unity.h"', file=of)
    print('#include "tinycrypt/sha3.h"', file=of)

    for test_group in [
        "SHAKE128LongMsg",
        "SHAKE128ShortMsg",
        "SHAKE256LongMsg",
        "SHAKE256ShortMsg",
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
                elif line.startswith("Output"):
                    print(
                        f"static uint8_t {test_group}_DIGEST{vecno}[] = "
                        + "{0x"
                        + ",0x".join(
                            [line[9:-1][i : i + 2] for i in range(0, len(line) - 10, 2)]
                        )
                        + ",};",
                        file=of,
                    )
                    vecno += 1
        for i in range(vecno):
            print(f"void test_{test_group}{i} (void)", file=of)
            print("{", file=of)
            if "256" in test_group:
                print("uint8_t actual_digest[32];", file=of)
                print(
                    f"tct_shake_full({test_group}_MSG{i}, sizeof({test_group}_MSG{i}), 256, actual_digest, 32);",
                    file=of,
                )
                print(
                    f"TEST_ASSERT_EQUAL_HEX8_ARRAY({test_group}_DIGEST{i}, actual_digest, 32);",
                    file=of,
                )
            else:
                print("uint8_t actual_digest[16];", file=of)
                print(
                    f"tct_shake_full({test_group}_MSG{i}, sizeof({test_group}_MSG{i}), 128, actual_digest, 16);",
                    file=of,
                )
                print(
                    f"TEST_ASSERT_EQUAL_HEX8_ARRAY({test_group}_DIGEST{i}, actual_digest, 16);",
                    file=of,
                )
            print("}", file=of)

    for test_group in [
        "SHAKE128VariableOut",
        "SHAKE256VariableOut",
    ]:
        vecno = 0
        with open(BASE_PATH + test_group + ".rsp") as f:
            out_len = 0
            cur_len = 32 if "256" in test_group else 16
            for line in f:
                if line.startswith("Outputlen"):
                    out_len = int(line[12:-1]) // 8
                elif line.startswith("Msg"):
                    print(
                        f"static uint8_t {test_group}_MSG{vecno}[{cur_len}] = "
                        + "{0x"
                        + ",0x".join(
                            [line[6:-1][i : i + 2] for i in range(0, len(line) - 7, 2)]
                        )
                        + ",};",
                        file=of,
                    )
                elif line.startswith("Output"):
                    print(
                        f"static uint8_t {test_group}_DIGEST{vecno}[{out_len}] = "
                        + "{0x"
                        + ",0x".join(
                            [line[9:-1][i : i + 2] for i in range(0, len(line) - 10, 2)]
                        )
                        + ",};",
                        file=of,
                    )
                    print(f"void test_{test_group}{vecno} (void)", file=of)
                    print("{", file=of)
                    print(f"uint8_t actual_digest[{out_len}];", file=of)
                    if "256" in test_group:
                        print(
                            f"tct_shake_full({test_group}_MSG{vecno}, sizeof({test_group}_MSG{vecno}), 256, actual_digest, {out_len});",
                            file=of,
                        )
                    else:
                        print(
                            f"tct_shake_full({test_group}_MSG{vecno}, sizeof({test_group}_MSG{vecno}), 128, actual_digest, {out_len});",
                            file=of,
                        )
                    print(
                        f"TEST_ASSERT_EQUAL_HEX8_ARRAY({test_group}_DIGEST{vecno}, actual_digest, {out_len});",
                        file=of,
                    )
                    print("}", file=of)
                    vecno += 1

    for test_group in [
        "SHAKE128Monte",
        "SHAKE256Monte",
    ]:
        with open(BASE_PATH + test_group + ".rsp") as f:
            out_lens = []
            for line in f:
                if line.startswith("Outputlen"):
                    out_lens.append(int(line[12:-1]) // 8)
                elif line.startswith("Msg"):
                    print(
                        f"static uint8_t {test_group}_MSG[16] = "
                        + "{0x"
                        + ",0x".join(
                            [line[6:-1][i : i + 2] for i in range(0, len(line) - 7, 2)]
                        )
                        + ",};",
                        file=of,
                    )
                elif line.startswith("Output"):
                    print(
                        f"static uint8_t {test_group}_DIGEST{len(out_lens) - 1}[{out_lens[-1]}] = "
                        + "{0x"
                        + ",0x".join(
                            [line[9:-1][i : i + 2] for i in range(0, len(line) - 10, 2)]
                        )
                        + ",};",
                        file=of,
                    )
            print(f"void test_{test_group} (void)", file=of)
            print("{", file=of)
            print("uint8_t digest[250];", file=of)
            print("uint8_t msg[250];", file=of)
            print(
                f"for (uint8_t i = 0; i < 16; ++i) msg[i] = {test_group}_MSG[i];",
                file=of,
            )
            print(
                f"uint16_t output_len = {250 if '256' in test_group else 140};", file=of
            )
            len_range = 249 if "256" in test_group else 125
            minoutbytes = 2 if "256" in test_group else 16
            for i in range(100):
                print("for (uint16_t j = 0; j < 1000; ++j)", file=of)
                print("{", file=of)
                if "256" in test_group:
                    print(
                        "tct_shake_full(msg, 16, 256, digest, output_len);",
                        file=of,
                    )
                else:
                    print(
                        "tct_shake_full(msg, 16, 128, digest, output_len);",
                        file=of,
                    )
                print(
                    "for (uint16_t i = 0; i < output_len; ++i) msg[i] = digest[i];",
                    file=of,
                )
                print(
                    "for (uint16_t i = output_len; i < 16; ++i) msg[i] = 0x0;",
                    file=of,
                )
                print("if (j == 999)", file=of)
                print(f"TEST_ASSERT_EQUAL_UINT16({out_lens[i]}, output_len);", file=of)
                print(
                    f"output_len = {minoutbytes} + (((digest[output_len - 2] << 8) | (digest[output_len - 1])) % {len_range});",
                    file=of,
                )
                print("}", file=of)
                print(
                    f"TEST_ASSERT_EQUAL_HEX8_ARRAY({test_group}_DIGEST{i}, digest, {out_lens[i]});",
                    file=of,
                )
            print("}", file=of)
