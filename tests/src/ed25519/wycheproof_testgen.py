import json
import sys

WYCHEPROOF_FILE = sys.argv[1]

with open(WYCHEPROOF_FILE, "r") as f:
    contents = json.load(f)

with open(sys.argv[2], "w") as of:
    print("#include <stdint.h>", file=of)
    print("#include <stdbool.h>", file=of)
    print('#include "unity.h"', file=of)
    print('#include "tinycrypt/ed25519.h"', file=of)

    for test_group in contents["testGroups"]:
        group_type = test_group["type"]
        for test in test_group["tests"]:
            if len(test["sig"]) != 128:
                # TinyCrypT is a C library and always assumes the signature is the same length because that's how C arrays work.
                # As such, it's the *user* of TinyCrypT that has to worry about truncated or compressed signatures.
                continue
            print(f"void test_{group_type}_{test['tcId']} (void)", file=of)
            print("{", file=of)
            print(
                "const uint8_t PK[32] = {"
                + ",".join(
                    [
                        "0x" + test_group["publicKey"]["pk"][i : i + 2]
                        for i in range(0, len(test_group["publicKey"]["pk"]), 2)
                    ]
                )
                + "};",
                file=of,
            )
            print(
                "const uint8_t SIG[64] = {"
                + ",".join(
                    [
                        "0x" + test["sig"][i : i + 2]
                        for i in range(0, len(test["sig"]), 2)
                    ]
                )
                + "};",
                file=of,
            )
            print(
                "const uint8_t MSG[] = {"
                + ",".join(
                    [
                        "0x" + test["msg"][i : i + 2]
                        for i in range(0, len(test["msg"]), 2)
                    ]
                )
                + "};",
                file=of,
            )
            print("uint8_t working_buf[sizeof(MSG) + 64];", file=of)
            if test["result"] == "valid":
                print("TEST_ASSERT_TRUE(", end="", file=of)
            else:
                print("TEST_ASSERT_FALSE(", end="", file=of)
            print(
                "tct_ed25519_verify(PK, MSG, sizeof(MSG), working_buf, SIG));", file=of
            )
            print("}", file=of)
