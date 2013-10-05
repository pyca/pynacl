"""
CFFI interface to NaCl and libsodium library
"""
from __future__ import absolute_import
from __future__ import division

import functools

from distutils.sysconfig import get_config_vars

import cffi.verifier

from cffi import FFI


__all__ = ["ffi", "lib"]


# Monkeypatch cffi.verifier._get_so_suffix to return the same as distutils
# See: https://bitbucket.org/cffi/cffi/issue/110/
def _get_so_suffix():
    return get_config_vars().get("EXT_SUFFIX", ".so")

cffi.verifier._get_so_suffix = _get_so_suffix


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


ffi.verifier = cffi.verifier.Verifier(ffi,
    "#include <sodium.h>",

    # We need to link to the sodium library
    libraries=["sodium"],

    # Our ext_package is nacl so look for it
    ext_package="nacl",
)


# This works around a bug in PyPy where CFFI exposed functions do not have a
# __name__ attribute. See https://bugs.pypy.org/issue1452
def wraps(wrapped):
    def inner(func):
        if hasattr(wrapped, "__name__"):
            return functools.wraps(wrapped)(func)
        else:
            return func
    return inner


# A lot of the functions in nacl return 0 for success and a negative integer
# for failure. This is inconvenient in Python as 0 is a falsey value while
# negative integers are truthy. This wrapper has them return True/False as
# you'd expect in Python
def wrap_nacl_function(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        return ret == 0
    return wrapper


class Library(object):

    wrap = [
        "crypto_secretbox",
        "crypto_secretbox_open",

        "crypto_sign_seed_keypair",
        "crypto_sign",
        "crypto_sign_open",

        "crypto_box_keypair",
        "crypto_box_afternm",
        "crypto_box_open_afternm",
        "crypto_box_beforenm",

        "crypto_hash",
        "crypto_hash_sha256",
        "crypto_hash_sha512",

        "crypto_scalarmult_curve25519_base",
    ]

    def __init__(self, ffi):
        self._ffi = ffi
        self._initalized = False

        # This prevents the compile_module() from being called, the module
        # should have been compiled by setup.py
        def _compile_module(*args, **kwargs):
            raise RuntimeError("Cannot compile module during runtime")
        self._ffi.verifier.compile_module = _compile_module

    def __getattr__(self, name):
        if not self._initalized:
            self._lib = self._ffi.verifier.load_library()

        # redirect attribute access to the underlying lib
        attr = getattr(self._lib, name)

        # If this is a function that we're wrapping do the actual wrapping
        if name in self.wrap:
            attr = wrap_nacl_function(attr)

        # Go ahead and assign the returned value to this class so we don't
        # need to do this lookup again
        setattr(self, name, attr)

        return attr

lib = Library(ffi)
