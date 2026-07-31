import json
import sys

WYCHEPROOF_FILE = sys.argv[1]

with open(WYCHEPROOF_FILE, "r") as f:
    contents = json.load(f)

print("#include <stdint.h>")
print("#include <stdbool.h>")
print("#include \"gtest/gtest.h\"")
print("extern \"C\" {")
print("#include \"tinycrypt/x25519.h\"")
print("}")

for test_group in contents["testGroups"]:
    group_type = test_group["type"]
    for test in test_group["tests"]:
        print(f"TEST ({group_type}, {test['tcId']})")
        print("{")
        print("const uint8_t PUBLIC[32] = {" + ",".join(["0x" + test["public"][i:i+2] for i in range(0, len(test["public"]), 2)]) + "};")
        print("const uint8_t PRIVATE[32] = {" + ",".join(["0x" + test["private"][i:i+2] for i in range(0, len(test["private"]), 2)]) + "};")
        print("const uint8_t EXPECTED[32] = {" + ",".join(["0x" + test["shared"][i:i+2] for i in range(0, len(test["shared"]), 2)]) + "};")
        print("uint8_t actual[32];")
        print("tct_x25519(PRIVATE, PUBLIC, actual);")
        print("EXPECT_EQ(memcmp(actual, EXPECTED, 32), 0);")
        print("}")
