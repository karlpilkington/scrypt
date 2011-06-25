import hashlib

from itertools import izip

from salsa20 import salsa20core
from pbkdf2 import PBKDF2


__all__ = ['scrypt']

BLOCK_WORDS = 16


def blockmix_salsa20_8(B, r=8):
    Y = [None]*(2 * r * BLOCK_WORDS)
    even = 0
    odd = r * BLOCK_WORDS
    T = B[(2 * r - 1) * BLOCK_WORDS:]

    for i in range(0,2 * r * BLOCK_WORDS,2 * BLOCK_WORDS):
        for j in range(BLOCK_WORDS):
            T[j] ^= B[i + j]
        Y[even:even+BLOCK_WORDS] = T = salsa20core(T, rounds=8)
        even += BLOCK_WORDS
        
        for j in range(BLOCK_WORDS):
            T[j] ^= B[i + BLOCK_WORDS + j]
        Y[odd:odd+BLOCK_WORDS] = T = salsa20core(T, rounds=8)
        odd += BLOCK_WORDS
    return Y


def from_littleendian(b):
    return ord(b[0]) | (ord(b[1]) << 8) | (ord(b[2]) << 16) | (ord(b[3]) << 24)


def to_littleendian(w):
    return [chr(w & 0xff),
            chr((w >> 8) & 0xff),
            chr((w >> 16) & 0xff),
            chr((w >> 24) & 0xff)]


def smix(B, N, r=8):
    X = [from_littleendian(B[i:i+4]) for i in range(0,len(B),4)]
    V = []
    for i in range(N):
        V.append(X)
        X = blockmix_salsa20_8(X, r=r)
    for i in range(N):
        j = X[-BLOCK_WORDS] % N

        T = []
        for xk,vjk in izip(X, V[j]):
            T.append(xk ^ vjk)
        X = blockmix_salsa20_8(T, r=r)
    out = []
    for x in X:
        out.extend(to_littleendian(x))
    return ''.join(out)


def scrypt(password, salt, N, r, p, dkLen):
    MFLen = 2 * r * 64
    t = PBKDF2(password, salt, 1, p * MFLen, digestmod=hashlib.sha256)
    B = []
    while t:
        B.append(t[:MFLen])
        t = t[MFLen:]
    for i in range(p):
        B[i] = smix(B[i], N, r=r)
    return PBKDF2(password, ''.join(B), 1, dkLen, digestmod=hashlib.sha256)


if __name__ == '__main__':
    print(scrypt('', '', 16, 1, 1, 64).encode('hex'))
    #print(scrypt('password', 'NaCl', 1024, 8, 16, 64).encode('hex'))
    import timeit
    print(timeit.Timer("""scrypt('password', 'salt', 64, 8, 1, 64)""", 'from __main__ import scrypt').timeit(10))
