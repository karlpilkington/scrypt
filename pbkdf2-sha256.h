#ifndef _APS_PBKDF2_SHA256_H
#define _APS_PBKDF2_SHA256_H

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

#define PBKDF2 PBKDF2_SHA256

#include "_pbkdf2.h"

#ifndef _PBKDF2_INTERNAL
#undef PBKDF2
#endif /* !_PBKDF2_INTERNAL */

#endif /* !_APS_PBKDF2_SHA256_H */
