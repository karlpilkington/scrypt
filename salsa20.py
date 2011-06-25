from itertools import izip


__all__ = ['salsa20']

MASK32 = 2**32-1


def rotl(n, r):
    return ((n << r) & MASK32) | ((n & MASK32) >> (32 - r))


def quarterround(y):
    z = [None]*4
    z[1] = y[1] ^ rotl(y[0] + y[3], 7)
    z[2] = y[2] ^ rotl(z[1] + y[0], 9)
    z[3] = y[3] ^ rotl(z[2] + z[1], 13)
    z[0] = y[0] ^ rotl(z[3] + z[2], 18)
    return z


def rowround(y):
    z = [None]*16
    z[ 0], z[ 1], z[ 2], z[ 3] = quarterround((y[ 0], y[ 1], y[ 2], y[ 3]))
    z[ 5], z[ 6], z[ 7], z[ 4] = quarterround((y[ 5], y[ 6], y[ 7], y[ 4]))
    z[10], z[11], z[ 8], z[ 9] = quarterround((y[10], y[11], y[ 8], y[ 9]))
    z[15], z[12], z[13], z[14] = quarterround((y[15], y[12], y[13], y[14]))
    return z


def columnround(x):
    y = [None]*16
    y[ 0], y[ 4], y[ 8], y[12] = quarterround((x[ 0], x[ 4], x[ 8], x[12]))
    y[ 5], y[ 9], y[13], y[ 1] = quarterround((x[ 5], x[ 9], x[13], x[ 1]))
    y[10], y[14], y[ 2], y[ 6] = quarterround((x[10], x[14], x[ 2], x[ 6]))
    y[15], y[ 3], y[ 7], y[11] = quarterround((x[15], x[ 3], x[ 7], x[11]))
    return y


def doubleround(x):
    return rowround(columnround(x))


def littleendian(b):
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)


def littleendian_inv(w):
    return [w & 0xff,
            (w >> 8) & 0xff,
            (w >> 16) & 0xff,
            (w >> 24) & 0xff]


def salsa20(x, rounds=20):
    x = [littleendian(x[i:i+4]) for i in range(0,len(x),4)]
    z = x
    for i in range(rounds/2):
        z = doubleround(z)
    out = []
    for xi,zi in izip(x, z):
        out.extend(littleendian_inv(xi + zi))
    return out
