#ifndef crypto_scalarmult_curve25519_H
#define crypto_scalarmult_curve25519_H

#if 1
# ifndef SODIUM_HAVE_TI_MODE
#  define SODIUM_HAVE_TI_MODE
# endif
#endif

#include "export.h"

#define crypto_scalarmult_curve25519_BYTES 32
#define crypto_scalarmult_curve25519_SCALARBYTES 32

#ifdef __cplusplus
extern "C" {
#endif

SODIUM_EXPORT
int crypto_scalarmult_curve25519(unsigned char *,const unsigned char *,const unsigned char *);

SODIUM_EXPORT
int crypto_scalarmult_curve25519_base(unsigned char *,const unsigned char *);

#ifdef SODIUM_HAVE_TI_MODE
# define crypto_scalarmult_curve25519_donna_c64 crypto_scalarmult_curve25519
# define crypto_scalarmult_curve25519_donna_c64_base crypto_scalarmult_curve25519_base
#else
# define crypto_scalarmult_curve25519_ref crypto_scalarmult_curve25519
# define crypto_scalarmult_curve25519_ref_base crypto_scalarmult_curve25519_base
#endif

#ifdef __cplusplus
}
#endif

#endif
