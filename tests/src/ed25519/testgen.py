# Modify as necessary, generates GoogleTest harnesses from the provided test inputs

vecno = 0
print("#include <cstdint>")
print("#include <cstring>")
print("#include \"gtest/gtest.h\"")
print("extern \"C\" {")
print("#include \"tinycrypt/ed25519.h\"")
print("}")

with open("tests.inp") as f:
    for line in f:
        if line.startswith("SK"):
            print(f"static uint8_t SK{vecno}[] = " + "{0x" + ",0x".join([line[5:-1][i:i+2] for i in range(0, len(line) - 6, 2)]) + ",};")
        elif line.startswith("PK"):
            print(f"static uint8_t PK{vecno}[] = " + "{0x" + ",0x".join([line[5:-1][i:i+2] for i in range(0, len(line) - 6, 2)]) + ",};")
        elif line.startswith("MSG"):
            pass
            # Remember to cut out the `0x,` in an empty message if necessary 
            # print(f"static uint8_t MSG{vecno}[] = " + "{0x" + ",0x".join([line[5:-1][i:i+2] for i in range(0, len(line) - 6, 2)]) + ",};")
        elif line.startswith("SIG"):
            # print(f"static uint8_t SIG{vecno}[] = " + "{0x" + ",0x".join([line[5:-1][i:i+2] for i in range(0, len(line) - 6, 2)]) + ",};")
            vecno += 1

for i in range(vecno):
    print(f"TEST (TinyCrypT_Ed25519, ed25519_keygen_{i})")
    print("{")
    # print("uint8_t actual_signature[64];")
    print("uint8_t actual_pk[32];")
    print(f"tct_ed25519_keygen(SK{i}, actual_pk);")
    # print(f"uint8_t working_buf[sizeof(MSG{i}) + 64];")
    # print(f"tct_ed25519_sign (MSG{i}, sizeof(MSG{i}), SK{i}, PK{i}, working_buf, actual_signature);")
    # print(f"EXPECT_EQ(memcmp(SIG{i}, actual_signature, 64), 0);")
    print(f"EXPECT_EQ(memcmp(PK{i}, actual_pk, 32), 0);")
    # print(f"EXPECT_EQ(tct_ed25519_verify(PK{i}, MSG{i}, sizeof(MSG{i}), working_buf, SIG{i}), true);")
    # print(f"SIG{i}[{i} % 64] ^= 0b10101010;")
    # print(f"EXPECT_EQ(tct_ed25519_verify(PK{i}, MSG{i}, sizeof(MSG{i}), working_buf, SIG{i}), false);")
    print("}")