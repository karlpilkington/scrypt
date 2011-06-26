#ifndef _APS_SCRYPT_H
#define _APS_SCRYPT_H

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

int scrypt (const void *password, size_t passwordLen, const void *salt, size_t saltLen,
	    unsigned int N, unsigned int r, unsigned int p,
	    uint8_t *derivedKey, size_t dkLen);

#endif /* !_APS_SCRYPT_H */
