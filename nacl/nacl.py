"""
CFFI interface to NaCl and libsodium library
"""
from __future__ import absolute_import
from __future__ import division

import functools

from cffi import FFI


__all__ = ["ffi", "lib"]


# these are the constants we care about, written as if they were a cdef.
# Since since we're using ffi.dlopen() instead of ffi.verify(), we can't get
# constants this way. But for each one of these, libsodium provides a getter
# function named crypto_secretbox_keybytes(), which returns a size_t. We
# generate a cdef for the getter function, and then call it to populate the
# lib object later.

constants = {}
_constants = """
        static const int crypto_secretbox_KEYBYTES;
        static const int crypto_secretbox_NONCEBYTES;
        static const int crypto_secretbox_ZEROBYTES;
        static const int crypto_secretbox_BOXZEROBYTES;
        static const int crypto_sign_PUBLICKEYBYTES;
        static const int crypto_sign_SECRETKEYBYTES;
        static const int crypto_sign_BYTES;
        static const int crypto_box_PUBLICKEYBYTES;
        static const int crypto_box_SECRETKEYBYTES;
        static const int crypto_box_BEFORENMBYTES;
        static const int crypto_box_NONCEBYTES;
        static const int crypto_box_ZEROBYTES;
        static const int crypto_box_BOXZEROBYTES;
        static const int crypto_hash_sha256_BYTES;
        static const int crypto_hash_sha512_BYTES;
"""
for line in _constants.strip().splitlines():
    pieces = line.split()
    assert pieces[0:3] == ["static", "const", "int"]
    assert pieces[3].endswith(";")
    constant_name = pieces[3][:-1]
    getter_name = constant_name.lower()
    constants[constant_name] = getter_name

ffi = FFI()

for getter_name in constants.values():
    ffi.cdef("size_t %s(void);" % getter_name)

ffi.cdef(
    # Secret Key Encryption
    """
        int crypto_secretbox(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k);
        int crypto_secretbox_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
    """

    # Public Key Encryption - Signatures
    """
        int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk, unsigned char *seed);
        int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk);
        int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);
    """

    # Public Key Encryption
    """
        int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
        int crypto_box_afternm(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k);
        int crypto_box_open_afternm(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
        int crypto_box_beforenm(unsigned char *k, const unsigned char *pk, const unsigned char *sk);
    """

    # Hashing
    """
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

# we use a locally-compiled copy of libsodium, which we expect to find next
# to us, here in the source tree
from os.path import dirname, join, isdir, exists
prefix = join(dirname(__file__), "libsodium")
assert isdir(prefix), prefix
for ext in [".dylib", ".so", ".dll"]:
    fn = join(prefix, "lib", "libsodium"+ext)
    if exists(fn):
        rawlib = ffi.dlopen(fn)
        break
else:
    raise ValueError("Unable to find libsodium.* (.so/.dylib/.dll) file")

# apparently we cannot add or change attributes on an object returned by
# ffi.dlopen(), so we wrap the whole thing. This may be a CFFI bug (I got a
# stack overflow due to infinite recursion when I tried).

class WrappedLibSodium:
    pass
lib = WrappedLibSodium()
lib._rawlib = rawlib

for constant_name, getter_name in constants.items():
    f = getattr(rawlib, getter_name)
    setattr(lib, constant_name, f())

# This works around a bug in PyPy where CFFI exposed functions do not have a
#   __name__ attribute. See https://bugs.pypy.org/issue1452
def wraps(wrapped):
    def inner(func):
        if hasattr(wrapped, "__name__"):
            return functools.wraps(wrapped)(func)
        else:
            return func
    return inner


# A lot of the functions in nacl return 0 for success and a negative integer
#   for failure. This is inconvenient in Python as 0 is a falsey value while
#   negative integers are truthy. This wrapper has them return True/False as
#   you'd expect in Python
def wrap_nacl_function(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        return ret == 0
    return wrapper

def add_function(name):
    setattr(lib, name, wrap_nacl_function(getattr(rawlib, name)))

for name in ("""
    crypto_secretbox
    crypto_secretbox_open
    crypto_sign_seed_keypair
    crypto_sign
    crypto_sign_open
    crypto_box_keypair
    crypto_box_afternm
    crypto_box_open_afternm
    crypto_box_beforenm
    crypto_hash
    crypto_hash_sha256
    crypto_hash_sha512
    randombytes
    crypto_scalarmult_curve25519_base
""").strip().splitlines():
    add_function(name.strip())
