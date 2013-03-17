"""
CFFI interface to NaCl and libsodium library
"""
from __future__ import absolute_import
from __future__ import division

import functools

from cffi import FFI


__all__ = ["ffi", "lib"]


ffi = FFI()
ffi.cdef(
    # Secret Key Encryption
    """
        static const int crypto_secretbox_KEYBYTES;
        static const int crypto_secretbox_NONCEBYTES;
        static const int crypto_secretbox_ZEROBYTES;
        static const int crypto_secretbox_BOXZEROBYTES;

        int crypto_secretbox(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k);
        int crypto_secretbox_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
    """

    # Public Key Encryption - Signatures
    """
        static const int crypto_sign_PUBLICKEYBYTES;
        static const int crypto_sign_SECRETKEYBYTES;
        static const int crypto_sign_BYTES;

        int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk, unsigned char *seed);
        int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk);
        int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);
    """

    # Public Key Encryption
    """
        static const int crypto_box_PUBLICKEYBYTES;
        static const int crypto_box_SECRETKEYBYTES;
        static const int crypto_box_BEFORENMBYTES;
        static const int crypto_box_NONCEBYTES;
        static const int crypto_box_ZEROBYTES;
        static const int crypto_box_BOXZEROBYTES;

        int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
        int crypto_box_afternm(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k);
        int crypto_box_open_afternm(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
        int crypto_box_beforenm(unsigned char *k, const unsigned char *pk, const unsigned char *sk);
    """

    # Hashing
    """
        static const int crypto_hash_BYTES;
        static const int crypto_hash_sha256_BYTES;
        static const int crypto_hash_sha512_BYTES;

        int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen);
        int crypto_hash_sha256(unsigned char *out, const unsigned char *in, unsigned long long inlen);
        int crypto_hash_sha512(unsigned char *out, const unsigned char *in, unsigned long long inlen);
    """

    # Secure Random
    """
        void randombytes(unsigned char * const buf, const unsigned long long buf_len);
    """

    # Low Level - Scalar Multiplication
    """
        int crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n);
    """
)


lib = ffi.verify("#include <sodium.h>", libraries=["sodium"])


# A lot of the functions in nacl return 0 for success and a negative integer
#   for failure. This is inconvenient in Python as 0 is a falsey value while
#   negative integers are truthy. This wrapper has them return True/False as
#   you'd expect in Python
def wrap_nacl_function(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        return ret == 0
    return wrapper

lib.crypto_secretbox = wrap_nacl_function(lib.crypto_secretbox)
lib.crypto_secretbox_open = wrap_nacl_function(lib.crypto_secretbox_open)

lib.crypto_sign_seed_keypair = wrap_nacl_function(lib.crypto_sign_seed_keypair)
lib.crypto_sign = wrap_nacl_function(lib.crypto_sign)
lib.crypto_sign_open = wrap_nacl_function(lib.crypto_sign_open)

lib.crypto_box_keypair = wrap_nacl_function(lib.crypto_box_keypair)
lib.crypto_box_afternm = wrap_nacl_function(lib.crypto_box_afternm)
lib.crypto_box_open_afternm = wrap_nacl_function(lib.crypto_box_open_afternm)
lib.crypto_box_beforenm = wrap_nacl_function(lib.crypto_box_beforenm)

lib.crypto_hash = wrap_nacl_function(lib.crypto_hash)
lib.crypto_hash_sha256 = wrap_nacl_function(lib.crypto_hash_sha256)
lib.crypto_hash_sha512 = wrap_nacl_function(lib.crypto_hash_sha512)

lib.crypto_scalarmult_curve25519_base = wrap_nacl_function(lib.crypto_scalarmult_curve25519_base)
