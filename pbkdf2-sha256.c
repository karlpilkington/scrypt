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
#include <string.h>

#define _PBKDF2_INTERNAL
#include "pbkdf2-sha256.h"

#include "hmac-sha256.h"

#define HMAC_CONTEXT HMAC_SHA256_Context
#define HMAC_INIT HMAC_SHA256_Init
#define HMAC_UPDATE HMAC_SHA256_Update
#define HMAC_FINAL HMAC_SHA256_Final
#define HMAC_SIZE SHA256_HASH_SIZE

#include "_pbkdf2.c"
