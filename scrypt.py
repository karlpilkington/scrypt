import hashlib

from itertools import izip

from salsa20 import salsa20core
from pbkdf2 import PBKDF2


__all__ = ['scrypt']


def blockmix_salsa20_8(B, r=8):
    X = B[2 * r - 1]
    Y = []
    for b in B:
        t = []
        for x,bi in izip(X, b):
            t.append(x ^ bi)
        X = salsa20core(t, rounds=8)
        Y.append(X)
    return Y[0:2 * r:2] + Y[1:2 * r:2]


def smix(B, N, r=8):
    X = []
    while B:
        X.append([ord(c) for c in B[:64]])
        B = B[64:]
    V = []
    for i in range(N):
        V.append(X)
        X = blockmix_salsa20_8(X, r=r)
    for i in range(N):
        Blast = X[-1]
        j = Blast[0] | (Blast[1] << 8) | (Blast[2] << 16) | (Blast[3] << 24)
        j %= N

        tk = []
        for k in range(2 * r):
            t = []
            for xk,vjk in izip(X[k], V[j][k]):
                t.append(xk ^ vjk)
            tk.append(t)
        X = blockmix_salsa20_8(tk, r=r)
    return ''.join([''.join([chr(c) for c in x]) for x in X])


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
    print(scrypt('password', 'NaCl', 1024, 8, 16, 64).encode('hex'))
    import timeit
    print(timeit.Timer("""scrypt('password', 'salt', 64, 8, 1, 64)""", 'from __main__ import scrypt').timeit(10))
