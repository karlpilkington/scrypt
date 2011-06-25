from itertools import izip


__all__ = ['salsa20core']

MASK32 = 2**32-1


def rotl(n, r):
    return ((n << r) & MASK32) | ((n & MASK32) >> (32 - r))


def doubleround(x):
    x[ 4] ^= rotl(x[ 0]+x[12], 7)
    x[ 8] ^= rotl(x[ 4]+x[ 0], 9)
    x[12] ^= rotl(x[ 8]+x[ 4],13)
    x[ 0] ^= rotl(x[12]+x[ 8],18)
    x[ 9] ^= rotl(x[ 5]+x[ 1], 7)
    x[13] ^= rotl(x[ 9]+x[ 5], 9)
    x[ 1] ^= rotl(x[13]+x[ 9],13)
    x[ 5] ^= rotl(x[ 1]+x[13],18)
    x[14] ^= rotl(x[10]+x[ 6], 7)
    x[ 2] ^= rotl(x[14]+x[10], 9)
    x[ 6] ^= rotl(x[ 2]+x[14],13)
    x[10] ^= rotl(x[ 6]+x[ 2],18)
    x[ 3] ^= rotl(x[15]+x[11], 7)
    x[ 7] ^= rotl(x[ 3]+x[15], 9)
    x[11] ^= rotl(x[ 7]+x[ 3],13)
    x[15] ^= rotl(x[11]+x[ 7],18)
    x[ 1] ^= rotl(x[ 0]+x[ 3], 7)
    x[ 2] ^= rotl(x[ 1]+x[ 0], 9)
    x[ 3] ^= rotl(x[ 2]+x[ 1],13)
    x[ 0] ^= rotl(x[ 3]+x[ 2],18)
    x[ 6] ^= rotl(x[ 5]+x[ 4], 7)
    x[ 7] ^= rotl(x[ 6]+x[ 5], 9)
    x[ 4] ^= rotl(x[ 7]+x[ 6],13)
    x[ 5] ^= rotl(x[ 4]+x[ 7],18)
    x[11] ^= rotl(x[10]+x[ 9], 7)
    x[ 8] ^= rotl(x[11]+x[10], 9)
    x[ 9] ^= rotl(x[ 8]+x[11],13)
    x[10] ^= rotl(x[ 9]+x[ 8],18)
    x[12] ^= rotl(x[15]+x[14], 7)
    x[13] ^= rotl(x[12]+x[15], 9)
    x[14] ^= rotl(x[13]+x[12],13)
    x[15] ^= rotl(x[14]+x[13],18)


def littleendian(b):
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)


def littleendian_inv(w):
    return [w & 0xff,
            (w >> 8) & 0xff,
            (w >> 16) & 0xff,
            (w >> 24) & 0xff]


def salsa20core(x, rounds=20):
    x = [littleendian(x[i:i+4]) for i in range(0,len(x),4)]
    z = list(x)
    for i in range(rounds/2):
        doubleround(z)
    out = []
    for xi,zi in izip(x, z):
        out.extend(littleendian_inv(xi + zi))
    return out
