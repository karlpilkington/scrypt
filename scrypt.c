/*-
 * Copyright (c) 2011 Allan Saddi <allan@saddi.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif

#include <stdlib.h>
#include <string.h>

#include "scrypt.h"
#include "pbkdf2-hmac-sha256.h"

#define BLOCK_WORDS 16

static inline uint32_t
ROTL(uint32_t x, int n)
{
  return (x << n) | (x >> (32 - n));
}

static inline uint32_t
ROTR(uint32_t x, int n)
{
  return (x >> n) | (x << (32 - n));
}

static inline uint32_t
BYTESWAP(uint32_t x)
{
  return (ROTR(x, 8) & 0xff00ff00) |
    (ROTL(x, 8) & 0x00ff00ff);
}

static void
salsa20_8_core (uint32_t out[BLOCK_WORDS], const uint32_t in[BLOCK_WORDS])
{
  const uint32_t *x;
  uint32_t *z;
  int i;

  memcpy(out, in, sizeof(*out) * BLOCK_WORDS);

  z = out;
  for (i = 8 - 1; i >= 0; i -= 2) {
    z[ 4] ^= ROTL(z[ 0]+z[12], 7);
    z[ 8] ^= ROTL(z[ 4]+z[ 0], 9);
    z[12] ^= ROTL(z[ 8]+z[ 4],13);
    z[ 0] ^= ROTL(z[12]+z[ 8],18);
    z[ 9] ^= ROTL(z[ 5]+z[ 1], 7);
    z[13] ^= ROTL(z[ 9]+z[ 5], 9);
    z[ 1] ^= ROTL(z[13]+z[ 9],13);
    z[ 5] ^= ROTL(z[ 1]+z[13],18);
    z[14] ^= ROTL(z[10]+z[ 6], 7);
    z[ 2] ^= ROTL(z[14]+z[10], 9);
    z[ 6] ^= ROTL(z[ 2]+z[14],13);
    z[10] ^= ROTL(z[ 6]+z[ 2],18);
    z[ 3] ^= ROTL(z[15]+z[11], 7);
    z[ 7] ^= ROTL(z[ 3]+z[15], 9);
    z[11] ^= ROTL(z[ 7]+z[ 3],13);
    z[15] ^= ROTL(z[11]+z[ 7],18);
    z[ 1] ^= ROTL(z[ 0]+z[ 3], 7);
    z[ 2] ^= ROTL(z[ 1]+z[ 0], 9);
    z[ 3] ^= ROTL(z[ 2]+z[ 1],13);
    z[ 0] ^= ROTL(z[ 3]+z[ 2],18);
    z[ 6] ^= ROTL(z[ 5]+z[ 4], 7);
    z[ 7] ^= ROTL(z[ 6]+z[ 5], 9);
    z[ 4] ^= ROTL(z[ 7]+z[ 6],13);
    z[ 5] ^= ROTL(z[ 4]+z[ 7],18);
    z[11] ^= ROTL(z[10]+z[ 9], 7);
    z[ 8] ^= ROTL(z[11]+z[10], 9);
    z[ 9] ^= ROTL(z[ 8]+z[11],13);
    z[10] ^= ROTL(z[ 9]+z[ 8],18);
    z[12] ^= ROTL(z[15]+z[14], 7);
    z[13] ^= ROTL(z[12]+z[15], 9);
    z[14] ^= ROTL(z[13]+z[12],13);
    z[15] ^= ROTL(z[14]+z[13],18);
  }

  x = in;
  for (i = BLOCK_WORDS - 1; i >= 0; i--) {
    *(z++) += *(x++);
  }
}

static void
blockmix_salsa20_8_core (uint32_t out[/* (2 * r * BLOCK_WORDS) */],
			 const uint32_t in[/* (2 * r * BLOCK_WORDS) */],
			 unsigned int r)
{
  uint32_t *even, *odd;
  uint32_t *x;
  uint32_t tmp[BLOCK_WORDS];
  unsigned int i, j;

  even = out;
  odd = &out[r * BLOCK_WORDS];

  memcpy(tmp, &in[(2 * r - 1) * BLOCK_WORDS], sizeof(tmp));

  for (i = r; i > 0; i--) {
    x = tmp;
    for (j = BLOCK_WORDS; j > 0; j--) {
      *(x++) ^= *(in++);
    }
    salsa20_8_core(even, tmp);
    memcpy(tmp, even, sizeof(tmp));
    even += BLOCK_WORDS;

    x = tmp;
    for (j = BLOCK_WORDS; j > 0; j--) {
      *(x++) ^= *(in++);
    }
    salsa20_8_core(odd, tmp);
    memcpy(tmp, odd, sizeof(tmp));
    odd += BLOCK_WORDS;
  }
}

static void
smix (void *out /* (sizeof(uint32_t) * 2 * r * BLOCK_WORDS) */,
      const void *in /* (sizeof(uint32_t) * 2 * r * BLOCK_WORDS) */,
      unsigned int N, unsigned int r,
      uint32_t tmp[/* (2 * r * BLOCK_WORDS * (N + 2)) */])
{
  uint32_t *v;
  uint32_t *X, *T, *x, *t;
  uint32_t j;
  unsigned int i, k;

  memcpy(tmp, in, sizeof(*tmp) * 2 * r * BLOCK_WORDS);

#ifdef WORDS_BIGENDIAN
  v = tmp;
  for (i = 2 * r * BLOCK_WORDS; i > 0; i--) {
    *v = BYTESWAP(*v);
    v++;
  }
#endif /* WORDS_BIGENDIAN */

  v = tmp;
  for (i = N; i > 0; i--) {
    blockmix_salsa20_8_core(v + 2 * r * BLOCK_WORDS, v, r);
    v += 2 * r * BLOCK_WORDS;
  }
  X = v;
  T = &X[2 * r * BLOCK_WORDS];

  for (i = N; i > 0; i--) {
    j = X[(2 * r - 1) * BLOCK_WORDS] % N;

    x = X;
    v = &tmp[2 * r * BLOCK_WORDS * j];
    for (k = 2 * r * BLOCK_WORDS; k > 0; k--) {
      *(x++) ^= *(v++);
    }

    blockmix_salsa20_8_core(T, X, r);

    /* swap X & T */
    t = T;
    T = X;
    X = t;
  }

#ifdef WORDS_BIGENDIAN
  x = X;
  for (i = 2 * r * BLOCK_WORDS; i > 0; i--) {
    *x = BYTESWAP(*x);
    x++;
  }
#endif /* WORDS_BIGENDIAN */

  memcpy (out, X, sizeof(*X) * 2 * r * BLOCK_WORDS);
}

int
scrypt (const void *password, size_t passwordLen,
	const void *salt, size_t saltLen,
	unsigned int N, unsigned int r, unsigned int p,
	uint8_t *derivedKey, size_t dkLen)
{
  size_t MFLen = sizeof(uint32_t) * 2 * r * BLOCK_WORDS;
  uint8_t *B, *b;
  uint32_t *tmp;
  unsigned int i;

  if ((B = malloc(p * MFLen)) == NULL)
    return -1;

  if (PBKDF2_HMAC_SHA256(password, passwordLen, salt, saltLen, 1,
			 B, p * MFLen))
    return -1;

  if ((tmp = malloc(sizeof(*tmp) * 2 * r * BLOCK_WORDS * (N + 2))) == NULL) {
    free(B);
    return -1;
  }

  b = B;
  for (i = p; i > 0; i--) {
    smix(b, b, N, r, tmp);
    b += MFLen;
  }

  if (PBKDF2_HMAC_SHA256(password, passwordLen, B, p * MFLen, 1,
			 derivedKey, dkLen))
    return -1;

  free(tmp);
  free(B);
  return 0;
}

#ifdef SCRYPT_TEST

#include <stdio.h>

static const uint8_t tv1[64] = {
  0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42,
  0xc1, 0x8a, 0x04, 0x97, 0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8,
  0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2, 0x14, 0x42, 0xfc, 0xd0, 0x06, 0x9d,
  0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17,
  0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28, 0xcf, 0x35, 0xe2, 0x0c,
  0x38, 0xd1, 0x89, 0x06
};

static const uint8_t tv2[64] = {
  0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19,
  0x0d, 0x01, 0xe9, 0xfe, 0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30,
  0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62, 0x2e, 0xaf, 0x30, 0xd9,
  0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda,
  0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d, 0x83, 0x60, 0xcb, 0xdf,
  0xa2, 0xcc, 0x06, 0x40
};

static const uint8_t tv3[64] = {
  0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48, 0x46, 0x1c, 0x06, 0xcd,
  0x81, 0xfd, 0x38, 0xeb, 0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e,
  0xa9, 0xb5, 0x43, 0xf6, 0x54, 0x5d, 0xa1, 0xf2, 0xd5, 0x43, 0x29, 0x55,
  0x61, 0x3f, 0x0f, 0xcf, 0x62, 0xd4, 0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9,
  0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40, 0xdf, 0xcf, 0x01, 0x7b,
  0x45, 0x57, 0x58, 0x87
};

static const uint8_t tv4[64] = {
  0x21, 0x01, 0xcb, 0x9b, 0x6a, 0x51, 0x1a, 0xae, 0xad, 0xdb, 0xbe, 0x09,
  0xcf, 0x70, 0xf8, 0x81, 0xec, 0x56, 0x8d, 0x57, 0x4a, 0x2f, 0xfd, 0x4d,
  0xab, 0xe5, 0xee, 0x98, 0x20, 0xad, 0xaa, 0x47, 0x8e, 0x56, 0xfd, 0x8f,
  0x4b, 0xa5, 0xd0, 0x9f, 0xfa, 0x1c, 0x6d, 0x92, 0x7c, 0x40, 0xf4, 0xc3,
  0x37, 0x30, 0x40, 0x49, 0xe8, 0xa9, 0x52, 0xfb, 0xcb, 0xf4, 0x5c, 0x6f,
  0xa7, 0x7a, 0x41, 0xa4
};

static void
print_hex (const void *buf, size_t len)
{
  unsigned int i;

  for (i = 0; i < len;) {
    printf ("%02x", ((uint8_t *)buf)[i++]);
    if (!(i % 4)) printf (" ");
    if (!(i % 32)) printf ("\n");
  }
  if (i % 32) printf ("\n");
}

static int
test_harness (const uint8_t *tv,
	      const void *password, size_t passwordLen,
	      const void *salt, size_t saltLen,
	      unsigned int N, unsigned int r, unsigned int p,
	      size_t dkLen)
{
  uint8_t out[64];
  int fail;

  scrypt(password, passwordLen, salt, saltLen, N, r, p, out, dkLen);
  print_hex(out, dkLen);
  fail = memcmp(tv, out, dkLen);
  printf("%s\n", !fail ? "PASS" : "FAIL");

  return fail;
}


int
main (int argc, char *argv[])
{
  int success = 0;

  printf("scrypt #1:\n");
  success += test_harness(tv1, "", 0, "", 0, 16, 1, 1, 64);

  printf("scrypt #2:\n");
  success += test_harness(tv2, "password", 8, "NaCl", 4, 1024, 8, 16, 64);

  printf("scrypt #3:\n");
  success += test_harness(tv3, "pleaseletmein", 13, "SodiumChloride", 14, 16384, 8, 1, 64);

  printf("scrypt #4:\n");
  success += test_harness(tv4, "pleaseletmein", 13, "SodiumChloride", 14, 1048576, 8, 1, 64);

  return success;
}
#endif /* SCRYPT_TEST */
