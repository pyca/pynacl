# Copyright 2013 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import absolute_import, division, print_function

import sys

import nacl.exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure


crypto_pwhash_scryptsalsa208sha256_SALTBYTES = \
    lib.crypto_pwhash_scryptsalsa208sha256_saltbytes()
crypto_pwhash_scryptsalsa208sha256_STRBYTES = \
    lib.crypto_pwhash_scryptsalsa208sha256_strbytes()
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE = \
    lib.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive()
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE = \
    lib.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive()
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE = \
    lib.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive()
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE = \
    lib.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive()

SCRYPT_OPSLIMIT_INTERACTIVE = \
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
SCRYPT_MEMLIMIT_INTERACTIVE = \
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE
SCRYPT_OPSLIMIT_SENSITIVE = \
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE
SCRYPT_MEMLIMIT_SENSITIVE = \
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE
SCRYPT_SALTBYTES = \
    crypto_pwhash_scryptsalsa208sha256_SALTBYTES
SCRYPT_STRBYTES = \
    crypto_pwhash_scryptsalsa208sha256_STRBYTES

SCRYPT_PR_MAX = ((1 << 30) - 1)
LOG2_UINT64_MAX = 63
UINT64_MAX = (1 << 64) - 1
SCRYPT_MAX_MEM = 32 * (1024 * 1024)


def _check_memory_occupation(n, r, p, maxmem=SCRYPT_MAX_MEM):
    ensure(r != 0, 'Invalid block size',
           raising=exc.ValueError)

    ensure(p != 0, 'Invalid parallelization factor',
           raising=exc.ValueError)

    ensure((n & (n-1)) == 0, 'Cost factor must be a power of 2',
           raising=exc.ValueError)

    ensure(n > 1, 'Cost factor must be at least 2',
           raising=exc.ValueError)

    ensure(p <= SCRYPT_PR_MAX / r, 'p*r is greater than {0}'.format(
                                                                SCRYPT_PR_MAX),
           raising=exc.ValueError)

    ensure(n < (1 << (16*r)),
           raising=exc.ValueError)

    Blen = p * 128 * r

    i = UINT64_MAX / 128

    ensure(n + 2 <= i / r,
           raising=exc.ValueError)

    Vlen = 32 * r * (n + 2) * 4

    ensure(Blen <= UINT64_MAX - Vlen,
           raising=exc.ValueError)

    ensure(Blen <= sys.maxsize - Vlen,
           raising=exc.ValueError)

    ensure(Blen + Vlen <= maxmem,
           'Memory limit would be exceeded with the choosen n, r, p',
           raising=exc.ValueError)


def nacl_bindings_pick_scrypt_params(opslimit, memlimit):
    """Python implementation of libsodium's pickparams"""

    if opslimit < 32768:
        opslimit = 32768

    r = 8

    if opslimit < (memlimit // 32):
        p = 1
        maxn = opslimit // (4 * r)
        for n_log2 in range(1, 63):  # pragma: no branch
            if (2 ** n_log2) > (maxn // 2):
                break
    else:
        maxn = memlimit // (r * 128)
        for n_log2 in range(1, 63):  # pragma: no branch
            if (2 ** n_log2) > maxn // 2:
                break

        maxrp = (opslimit // 4) // (2 ** n_log2)

        if maxrp > 0x3fffffff:  # pragma: no cover
            maxrp = 0x3fffffff

        p = maxrp // r

    return n_log2, r, p


def crypto_pwhash_scryptsalsa208sha256_ll(passwd, salt, n, r, p, dklen=64,
                                          maxmem=SCRYPT_MAX_MEM):
    """
    Derive a cryptographic key using the ``passwd`` and ``salt``
    given as input.

    The work factor can be tuned by by picking different
    values for the parameters

    :param bytes passwd:
    :param bytes salt:
    :param bytes salt: *must* be *exactly* :py:const:`.SALTBYTES` long
    :param int dklen:
    :param int opslimit:
    :param int n:
    :param int r: block size,
    :param int p: the parallelism factor
    :param int maxmem: the maximum available memory available for scrypt's
                       operations
    :rtype: bytes
    """
    ensure(isinstance(n, int),
           raising=TypeError)
    ensure(isinstance(r, int),
           raising=TypeError)
    ensure(isinstance(p, int),
           raising=TypeError)

    ensure(isinstance(passwd, bytes),
           raising=TypeError)
    ensure(isinstance(salt, bytes),
           raising=TypeError)

    _check_memory_occupation(n, r, p, maxmem)

    buf = ffi.new("uint8_t[]", dklen)

    ret = lib.crypto_pwhash_scryptsalsa208sha256_ll(passwd, len(passwd),
                                                    salt, len(salt),
                                                    n, r, p,
                                                    buf, dklen)

    ensure(ret == 0, 'Unexpected failure in key derivation',
           raising=exc.RuntimeError)

    return ffi.buffer(ffi.cast("char *", buf), dklen)[:]


def crypto_pwhash_scryptsalsa208sha256_str(
        passwd, opslimit=SCRYPT_OPSLIMIT_INTERACTIVE,
        memlimit=SCRYPT_MEMLIMIT_INTERACTIVE):
    """
    Derive a cryptographic key using the ``passwd`` and ``salt``
    given as input, returning a string representation which includes
    the salt and the tuning parameters.

    The returned string can be directly stored as a password hash.

    See :py:func:`.crypto_pwhash_scryptsalsa208sha256` for a short
    discussion about ``opslimit`` and ``memlimit`` values.

    :param bytes passwd:
    :param int opslimit:
    :param int memlimit:
    :return: serialized key hash, including salt and tuning parameters
    :rtype: bytes
    """
    buf = ffi.new("char[]", SCRYPT_STRBYTES)

    ret = lib.crypto_pwhash_scryptsalsa208sha256_str(buf, passwd,
                                                     len(passwd),
                                                     opslimit,
                                                     memlimit)

    ensure(ret == 0, 'Unexpected failure in password hashing',
           raising=exc.RuntimeError)

    return ffi.string(buf)


def crypto_pwhash_scryptsalsa208sha256_str_verify(passwd_hash, passwd):
    """
    Verifies the ``passwd`` against the ``passwd_hash`` that was generated.
    Returns True or False depending on the success

    :param passwd_hash: bytes
    :param passwd: bytes
    :rtype: boolean
    """

    ensure(len(passwd_hash) == SCRYPT_STRBYTES - 1, 'Invalid password hash',
           raising=exc.ValueError)

    ret = lib.crypto_pwhash_scryptsalsa208sha256_str_verify(passwd_hash,
                                                            passwd,
                                                            len(passwd))
    ensure(ret == 0,
           "Wrong password",
           raising=exc.InvalidkeyError)
    # all went well, therefore:
    return True
