import hashlib
import hmac
import struct


__all__ = ['PBKDF2']


DEFAULT_DIGESTMOD = hashlib.sha1


def f(password, salt, itercount, i, digestmod):
    U = hmac.new(password, salt + struct.pack('>i', i), digestmod).digest()
    result = [ord(x) for x in U]
    for j in range(1, itercount):
        U = hmac.new(password, U, digestmod).digest()

        U_result = [ord(x) for x in U]
        for x in range(len(U_result)):
            result[x] ^= U_result[x]
    return ''.join([chr(x) for x in result])


def PBKDF2(password, salt, itercount, dklen, digestmod=DEFAULT_DIGESTMOD, digest_size=None):
    if digest_size is None:
        digest_size = digestmod().digest_size

    if dklen > (2**32-1) * digest_size:
        raise ValueError, 'derived key too long'

    l = (dklen + digest_size - 1) / digest_size

    dk = []
    for i in range(1, l+1):
        dk.append(f(password, salt, itercount, i, digestmod))
    return ''.join(dk)[:dklen]


if __name__ == '__main__':
    assert PBKDF2('password', 'salt', 1, 20).encode('hex') == \
        '0c60c80f961f0e71f3a9b524af6012062fe037a6'

    assert PBKDF2('password', 'salt', 2, 20).encode('hex') == \
        'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'

    assert PBKDF2('password', 'salt', 4096, 20).encode('hex') == \
        '4b007901b765489abead49d926f721d065a429c1'

    #assert PBKDF2('password', 'salt', 16777216, 20).encode('hex') == \
    #    'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984'

    assert PBKDF2('passwordPASSWORDpassword',
                  'saltSALTsaltSALTsaltSALTsaltSALTsalt',
                  4096,
                  25).encode('hex') == \
                  '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'

    assert PBKDF2('pass\x00word', 'sa\x00lt', 4096, 16).encode('hex') == \
        '56fa6aa75548099dcc37d7f03425e0c3'
