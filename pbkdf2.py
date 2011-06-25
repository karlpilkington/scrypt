import hashlib
import hmac
import struct


__all__ = ['PBKDF2']


HLEN = hashlib.sha256().digest_size


def f(password, salt, itercount, i):
    U = hmac.new(password, salt + struct.pack('>i', i), hashlib.sha256).digest()
    result = [ord(x) for x in U]
    for j in range(1, itercount):
        U = hmac.new(password, U, hashlib.sha256).digest()

        U_result = [ord(x) for x in U]
        for x in range(len(U_result)):
            result[x] ^= U_result[x]
    return ''.join([chr(x) for x in result])


def PBKDF2(password, salt, itercount, dklen):
    if dklen > (2**32-1) * HLEN:
        raise ValueError, 'derived key too long'

    l = (dklen + HLEN - 1) / HLEN

    dk = []
    for i in range(1, l+1):
        dk.append(f(password, salt, itercount, i))
    return ''.join(dk)[:dklen]

