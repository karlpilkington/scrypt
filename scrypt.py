from salsa20 import salsa20
from pbkdf2 import PBKDF2

def blockmix_salsa20_8(B, r=8):
    X = B[2 * r - 1]
    Y = []
    for i in range(2 * r):
        X = [ord(c) for c in X]
        Bi = [ord(c) for c in B[i]]
        for j in range(64):
            X[j] ^= Bi[j]
        X = ''.join([chr(c) for c in X])
        X = salsa20(X, rounds=8)
        Y.append(X)
    Bout = []
    for i in range(0, 2 * r, 2):
        Bout.append(Y[i])
    for i in range(1, 2 * r, 2):
        Bout.append(Y[i])
    return Bout

def romix_blockmix_salsa20_8(B, N, r=8):
    X = []
    while B:
        X.append(B[:64])
        B = B[64:]
    V = []
    for i in range(N):
        V.append(X)
        X = blockmix_salsa20_8(X, r=r)
    for i in range(N):
        Bm1 = [ord(c) for c in X[-1]]
        j = Bm1[0] | (Bm1[1] << 8) | (Bm1[2] << 16) | (Bm1[3] << 24)
        j %= N

        Xt = []
        for k in range(2 * r):
            Xk = [ord(c) for c in X[k]]
            Vj = [ord(c) for c in V[j][k]]
            for l in range(64):
                Xk[l] ^= Vj[l]
            Xk = ''.join(chr(c) for c in Xk)
            Xt.append(Xk)
        X = blockmix_salsa20_8(Xt, r=r)
    return ''.join(X)

def scrypt(password, salt, N, r, p, dkLen):
    MFLen = 2 * r * 64
    t = PBKDF2(password, salt, 1, p * MFLen)
    B = []
    while t:
        B.append(t[:MFLen])
        t = t[MFLen:]
    for i in range(p):
        B[i] = romix_blockmix_salsa20_8(B[i], N, r=r)
    return PBKDF2(password, ''.join(B), 1, dkLen)


if __name__ == '__main__':
    print(scrypt('', '', 16, 1, 1, 64).encode('hex'))
    print(scrypt('password', 'NaCl', 1024, 8, 16, 64).encode('hex'))
