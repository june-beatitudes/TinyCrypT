import json
import sys

WYCHEPROOF_FILE = sys.argv[1]
OUTPUT_FILE = sys.argv[2]

with open(WYCHEPROOF_FILE, "r") as f:
    contents = json.load(f)

with open(OUTPUT_FILE, "w") as of:
    print("#include <stdint.h>", file=of)
    print("#include <stdbool.h>", file=of)
    print('#include "unity.h"', file=of)
    print('#include "tinycrypt/x25519.h"', file=of)

    for test_group in contents["testGroups"]:
        group_type = test_group["type"]
        for test in test_group["tests"]:
            print(f"void test_{group_type}_{test['tcId']} (void)", file=of)
            print("{", file=of)
            print(
                "const uint8_t PUBLIC[32] = {"
                + ",".join(
                    [
                        "0x" + test["public"][i : i + 2]
                        for i in range(0, len(test["public"]), 2)
                    ]
                )
                + "};",
                file=of,
            )
            print(
                "const uint8_t PRIVATE[32] = {"
                + ",".join(
                    [
                        "0x" + test["private"][i : i + 2]
                        for i in range(0, len(test["private"]), 2)
                    ]
                )
                + "};",
                file=of,
            )
            print(
                "const uint8_t EXPECTED[32] = {"
                + ",".join(
                    [
                        "0x" + test["shared"][i : i + 2]
                        for i in range(0, len(test["shared"]), 2)
                    ]
                )
                + "};",
                file=of,
            )
            print("uint8_t actual[32];", file=of)
            print("tct_x25519(PRIVATE, PUBLIC, actual);", file=of)
            print("TEST_ASSERT_EQUAL_HEX8_ARRAY(EXPECTED, actual, 32);", file=of)
            print("}", file=of)
