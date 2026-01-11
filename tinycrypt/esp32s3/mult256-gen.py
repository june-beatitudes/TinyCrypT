print("xt_fastmult256:")
# `a0` is return address, `a1` is stack pointer, `a2` is input `a`, `a3` is input `b`, `a4` is output buffer
print(f"  movi a5, {4 * (16 * 9 + 1)}")
print("  sub a1, a1, a5")
print("  s32i a0, a1, 0")

# Time to generate the lookup table!
def add36(a, b, out):
    print(f"  l32i a6, {a}")
    print(f"  l32i a7, {b}")
    print("  add a8, a6, a7")
    print("  sub a9, a8, a6")
    print("  movi a10, 1")
    print("  xor a10, a10, a10")
    print("  movltz a11, a10, a9")

print("  xor a5, a5, a5")
print("  s32i a5, a1, 1")
for i in range(8):
    print(f"  l32i a5, a2, {i}")
    print(f"  s32i a5, a1, {2 + i}")
for i in range(1, 16):
    pass