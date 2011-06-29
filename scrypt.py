# Copyright (c) 2011 Allan Saddi <allan@saddi.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

__author__ = 'Allan Saddi <allan@saddi.com>'
__copyright__ = 'Copyright 2011 Allan Saddi'
__license__ = 'BSD'


import hashlib

from itertools import izip

from pbkdf2 import PBKDF2


__all__ = ['scrypt']

MASK32 = 2**32-1

BLOCK_WORDS = 16


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


def salsa20_8_core(x):
    z = list(x)
    for i in range(4):
        doubleround(z)
    for i in range(16):
        z[i] = (z[i] + x[i]) & MASK32
    return z


def blockmix_salsa20_8(B, r=8):
    Y = [None]*(2 * r * BLOCK_WORDS)
    even = 0
    odd = r * BLOCK_WORDS
    T = B[(2 * r - 1) * BLOCK_WORDS:]

    for i in range(0,2 * r * BLOCK_WORDS,2 * BLOCK_WORDS):
        for j in range(BLOCK_WORDS):
            T[j] ^= B[i + j]
        Y[even:even+BLOCK_WORDS] = T = salsa20_8_core(T)
        even += BLOCK_WORDS
        
        for j in range(BLOCK_WORDS):
            T[j] ^= B[i + BLOCK_WORDS + j]
        Y[odd:odd+BLOCK_WORDS] = T = salsa20_8_core(T)
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
    MFLen = 2 * r * 4 * BLOCK_WORDS
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
