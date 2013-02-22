"""
CFFI interface to libsodium the library
"""
import functools

from cffi import FFI


__all__ = ["ffi", "lib"]


ffi = FFI()
ffi.cdef(
    # pylint: disable=C0301

    # Low Level Hashing functions
    """
        static const int crypto_hash_BYTES;
        static const int crypto_hash_sha256_BYTES;
        static const int crypto_hash_sha512_BYTES;

        int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen);
        int crypto_hash_sha256(unsigned char *out, const unsigned char *in, unsigned long long inlen);
        int crypto_hash_sha512(unsigned char *out, const unsigned char *in, unsigned long long inlen);
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

lib.crypto_hash = wrap_nacl_function(lib.crypto_hash)
lib.crypto_hash_sha256 = wrap_nacl_function(lib.crypto_hash_sha256)
lib.crypto_hash_sha512 = wrap_nacl_function(lib.crypto_hash_sha512)
