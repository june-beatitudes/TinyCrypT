# Modify as necessary, generates GoogleTest harnesses from the NIST-provided testing files

vecno = 0
print("#include <cstdint>")
print("#include <cstring>")
print("#include \"gtest/gtest.h\"")
print("extern \"C\" {")
print("#include \"tinycrypt/sha2.h\"")
print("}")

# with open("SHA512LongMsg.rsp") as f:
#     for line in f:
#         if line.startswith("Msg"):
#             print(f"static uint8_t MSG{vecno}[] = " + "{0x" + ",0x".join([line[6:-1][i:i+2] for i in range(0, len(line) - 7, 2)]) + ",};")
#         elif line.startswith("MD"):
#             print(f"static uint8_t DIGEST{vecno}[] = " + "{0x" + ",0x".join([line[5:-1][i:i+2] for i in range(0, len(line) - 6, 2)]) + ",};")
#             vecno += 1

# for i in range(vecno):
#     print(f"TEST (TinyCrypT_SHA512, long_message_{i})")
#     print("{")
#     print("uint8_t actual_digest[64];")
#     print(f"tct_sha512(MSG{i}, sizeof(MSG{i}), actual_digest);")
#     print(f"EXPECT_EQ(memcmp(DIGEST{i}, actual_digest, 64), 0);")
#     print("}")

with open("SHA512Monte.rsp") as f:
    for line in f:
        if line.startswith("Seed"):
            print(f"static uint8_t SEED[] = " + "{0x" + ",0x".join([line[7:-1][i:i+2] for i in range(0, len(line) - 8, 2)]) + ",};")
        elif line.startswith("MD"):
            print(f"static uint8_t ROUND{vecno}[] = " + "{0x" + ",0x".join([line[5:-1][i:i+2] for i in range(0, len(line) - 6, 2)]) + ",};")
            vecno += 1

for i in range(vecno):
    print(f"TEST (TinyCrypT_SHA512, monte_{i})")
    print("{")
    print("uint8_t msg[192];")
    print("uint8_t digest[64];")
    print("uint8_t *a = msg; uint8_t *b = msg + 64; uint8_t *c = msg + 128;")
    print("for (uint64_t j = 0; j < 64; ++j) a[j] = b[j] = c[j] = SEED[j];")
    print(f"for (uint64_t i = 0; i < ({i} + 1) * 1000; ++i)")
    print("{")
    print("if (i % 1000 == 0 && i != 0) {")
    print("for (uint64_t j = 0; j < 64; ++j) a[j] = b[j] = c[j] = digest[j];")
    print("}")
    print(f"tct_sha512(msg, sizeof(msg), digest);")
    print("for (uint64_t j = 0; j < 64; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }")
    print("}")
    print(f"EXPECT_EQ(memcmp(ROUND{i}, digest, 64), 0);")
    print("}")