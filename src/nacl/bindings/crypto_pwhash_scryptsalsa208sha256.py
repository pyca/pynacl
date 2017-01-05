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

import nacl.exceptions as exc
from nacl._sodium import ffi, lib
from nacl.utils import ensure


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

OPSLIMIT_INTERACTIVE = \
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
MEMLIMIT_INTERACTIVE = \
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE
OPSLIMIT_SENSITIVE = \
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE
MEMLIMIT_SENSITIVE = \
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE
SALTBYTES = \
    crypto_pwhash_scryptsalsa208sha256_SALTBYTES
STRBYTES = \
    crypto_pwhash_scryptsalsa208sha256_STRBYTES


def crypto_pwhash_scryptsalsa208sha256(outlen, passwd, salt,
                                       opslimit=OPSLIMIT_SENSITIVE,
                                       memlimit=MEMLIMIT_SENSITIVE
                                       ):
    """
    Derive a cryptographic key using the ``passwd`` and ``salt``
    given as input.

    The work factor can be tuned by by picking different
    ``opslimit`` and ``memlimit``.

    The constants
        - :py:const:`.OPSLIMIT_INTERACTIVE`
        - :py:const:`.MEMLIMIT_INTERACTIVE`
        - :py:const:`.OPSLIMIT_SENSITIVE`
        - :py:const:`.MEMLIMIT_SENSITIVE`

    are provided as a guidance for correct settings respectively for the
    interactive login and the long term key protecting sensitive data
    usage cases.

    :param int outlen: int
    :param bytes passwd: bytes
    :param bytes salt: *must* be *exactly* :py:const:`.SALTBYTES` long
    :param int opslimit:
    :param int memlimit:
    :rtype: bytes
    """

    ensure(len(salt) == SALTBYTES, 'Invalid salt',
           raising=exc.ValueError)

    buf = ffi.new("unsigned char[]", outlen)

    ret = lib.crypto_pwhash_scryptsalsa208sha256(buf, outlen, passwd,
                                                 len(passwd), salt,
                                                 opslimit, memlimit)

    ensure(ret == 0, 'Unexpected failure in key derivation',
           raising=exc.RuntimeError)

    return ffi.buffer(buf, outlen)[:]


def crypto_pwhash_scryptsalsa208sha256_str(passwd,
                                           opslimit=OPSLIMIT_INTERACTIVE,
                                           memlimit=MEMLIMIT_INTERACTIVE
                                           ):
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
    buf = ffi.new("unsigned char[]", STRBYTES)

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

    ensure(len(passwd_hash) == STRBYTES - 1, 'Invalid password hash',
           raising=exc.ValueError)

    ret = lib.crypto_pwhash_scryptsalsa208sha256_str_verify(passwd_hash,
                                                            passwd,
                                                            len(passwd))
    ensure(ret == 0,
           "Wrong password",
           raising=exc.InvalidkeyError)
    # all went well, therefore:
    return True
