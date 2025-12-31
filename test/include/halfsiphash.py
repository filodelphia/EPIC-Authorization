# -----------------------------
# HalfSipHash-2-4 (word-exact like your P4)
# -----------------------------
def rotl32(x, b):
    x &= 0xFFFFFFFF
    return ((x << b) & 0xFFFFFFFF) | (x >> (32 - b))


def sipround(v0, v1, v2, v3):
    v0 = (v0 + v1) & 0xFFFFFFFF
    v2 = (v2 + v3) & 0xFFFFFFFF
    v1 = rotl32(v1, 5)
    v3 = rotl32(v3, 8)
    v1 ^= v0
    v3 ^= v2
    v0 = rotl32(v0, 16)
    v2 = (v2 + v1) & 0xFFFFFFFF
    v0 = (v0 + v3) & 0xFFFFFFFF
    v1 = rotl32(v1, 13)
    v3 = rotl32(v3, 7)
    v1 ^= v2
    v3 ^= v0
    v2 = rotl32(v2, 16)
    return v0, v1, v2, v3


def halfsiphash_2_4_32(k0, k1, m_words):
    const_0 = 0x00000000
    const_1 = 0x00000000
    const_2 = 0x6c796765
    const_3 = 0x74656462

    v0 = (k0 ^ const_0) & 0xFFFFFFFF
    v1 = (k1 ^ const_1) & 0xFFFFFFFF
    v2 = (k0 ^ const_2) & 0xFFFFFFFF
    v3 = (k1 ^ const_3) & 0xFFFFFFFF

    for m in m_words:
        m &= 0xFFFFFFFF
        v3 ^= m
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)
        v0 ^= m

    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = sipround(v0, v1, v2, v3)

    return (v1 ^ v3) & 0xFFFFFFFF


def swap16_halves(x):
    return ((x & 0xFFFF) << 16) | ((x >> 16) & 0xFFFF)


def u24(x):
    return x & 0xFFFFFF




if __name__ == '__main__':
    print("This is a module, not a standalone script.")
    exit(1)