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
#include "pbkdf2-sha256.h"

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

#define BLOCK_WORDS 16

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
			 const uint32_t in[/* (2 * r * BLOCK_WORDS) */], int r)
{
  uint32_t *even, *odd;
  uint32_t *x;
  uint32_t tmp[BLOCK_WORDS];
  int i, j;

  even = out;
  odd = &out[r * BLOCK_WORDS];

  memcpy(tmp, &in[(2 * r - 1) * BLOCK_WORDS], sizeof(tmp));

  for (i = r - 1; i >= 0; i--) {
    x = tmp;
    for (j = BLOCK_WORDS - 1; j >= 0; j--) {
      *(x++) ^= *(in++);
    }
    salsa20_8_core(even, tmp);
    memcpy(tmp, even, sizeof(tmp));
    even += BLOCK_WORDS;

    x = tmp;
    for (j = BLOCK_WORDS - 1; j >= 0; j--) {
      *(x++) ^= *(in++);
    }
    salsa20_8_core(odd, tmp);
    memcpy(tmp, odd, sizeof(tmp));
    odd += BLOCK_WORDS;
  }
}

static void
smix (void *out /* (sizeof(uint32_t) * 2 * r * BLOCK_WORDS) */,
      const void *in /* (sizeof(uint32_t) * 2 * r * BLOCK_WORDS) */, int N, int r,
      uint32_t tmp[/* (2 * r * BLOCK_WORDS * (N + 2)) */])
{
  uint32_t *v;
  uint32_t *X, *T, *x, *t;
  uint32_t j;
  int i, k;

  memcpy(tmp, in, sizeof(*tmp) * 2 * r * BLOCK_WORDS);

#ifdef WORDS_BIGENDIAN
  v = tmp;
  for (i = 2 * r * BLOCK_WORDS - 1; i >= 0; i--) {
    *v = BYTESWAP(*v);
    v++;
  }
#endif /* WORDS_BIGENDIAN */

  v = tmp;
  for (i = N - 1; i >= 0; i--) {
    blockmix_salsa20_8_core(v + 2 * r * BLOCK_WORDS, v, r);
    v += 2 * r * BLOCK_WORDS;
  }
  X = v;
  T = &X[2 * r * BLOCK_WORDS];

  for (i = N - 1; i >= 0; i--) {
    j = X[(2 * r - 1) * BLOCK_WORDS] % N;

    x = X;
    v = &tmp[2 * r * BLOCK_WORDS * j];
    for (k = 2 * r * BLOCK_WORDS - 1; k >= 0; k--) {
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
  for (i = 2 * r * BLOCK_WORDS - 1; i >= 0; i--) {
    *x = BYTESWAP(*x);
    x++;
  }
#endif /* WORDS_BIGENDIAN */

  memcpy (out, X, sizeof(*X) * 2 * r * BLOCK_WORDS);
}

int
scrypt (const void *password, size_t passwordLen, const void *salt, size_t saltLen, int N, int r, int p,
	uint8_t *derivedKey, size_t dkLen)
{
  int MFLen = sizeof(uint32_t) * 2 * r * BLOCK_WORDS;
  uint8_t *B, *b;
  uint32_t *tmp;
  int i;

  if ((B = malloc(p * MFLen)) == NULL)
    return -1;

  PBKDF2_SHA256(password, passwordLen, salt, saltLen, 1, B, p * MFLen);

  if ((tmp = malloc(sizeof(*tmp) * 2 * r * BLOCK_WORDS * (N + 2))) == NULL) {
    free(B);
    return -1;
  }

  b = B;
  for (i = p - 1; i >= 0; i--) {
    smix(b, b, N, r, tmp);
    b += MFLen;
  }

  PBKDF2_SHA256(password, passwordLen, B, p * MFLen, 1, derivedKey, dkLen);

  free(tmp);
  free(B);
  return 0;
}

#ifdef SCRYPT_TEST

#include <stdio.h>

static void
print_hex (uint8_t *s, int len)
{
  int i;

  for (i = 0; i < len;) {
    printf ("%02x", s[i++]);
    if (!(i % 4)) printf (" ");
    if (!(i % 32)) printf ("\n");
  }
  if (i % 32) printf ("\n");
}

int
main (int argc, char *argv[])
{
  uint8_t out[64];

  printf("scrypt #1:\n");
  scrypt("", 0, "", 0, 16, 1, 1, out, sizeof(out));
  print_hex(out, sizeof(out));

  printf("scrypt #2:\n");
  scrypt("password", 8, "NaCl", 4, 1024, 8, 16, out, sizeof(out));
  print_hex(out, sizeof(out));

  printf("scrypt #3:\n");
  scrypt("pleaseletmein", 13, "SodiumChloride", 14, 16384, 8, 1, out, sizeof(out));
  print_hex(out, sizeof(out));

  printf("scrypt #4:\n");
  scrypt("pleaseletmein", 13, "SodiumChloride", 14, 1048576, 8, 1, out, sizeof(out));
  print_hex(out, sizeof(out));

  return 0;
}
#endif /* SCRYPT_TEST */
