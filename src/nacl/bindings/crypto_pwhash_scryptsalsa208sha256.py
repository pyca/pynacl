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

from nacl._sodium import ffi, lib
from nacl.exceptions import CryptoError


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
    returns uses the ``passwd`` and ``salt`` to produce derive a key
    of ``outlen`` bytes can be tuned by picking different
    ``opslimit`` and ``memlimit``.

    The constants
        - :py:const:`.OPSLIMIT_INTERACTIVE`
        - :py:const:`.MEMLIMIT_INTERACTIVE`
        - :py:const:`.OPSLIMIT_SENSITIVE`
        - :py:const:`.MEMLIMIT_SENSITIVE`

    are provided as a guidance for correct settings respectively for the
    interactive login and the long term key protecting sensitive data
    usage cases.

    :param outlen: int
    :param passwd: bytes
    :param salt: bytes  *must* be *exactly* :py:const:`.SALTBYTES` long
    :param opslimit: int
    :param memlimit: int
    :rtype: bytes
    """

    if len(salt) != SALTBYTES:
        raise ValueError("Invalid salt")

    buf = ffi.new("unsigned char[]", outlen)

    ret = lib.crypto_pwhash_scryptsalsa208sha256(buf, outlen, passwd,
                                                 len(passwd), salt,
                                                 opslimit, memlimit)

    if ret != 0:
        raise CryptoError("Key derivation fails!")

    return ffi.buffer(buf, outlen)[:]


def crypto_pwhash_scryptsalsa208sha256_str(passwd,
                                           opslimit=OPSLIMIT_INTERACTIVE,
                                           memlimit=MEMLIMIT_INTERACTIVE
                                           ):
    """
    returns uses the ``passwd`` and ``salt`` and hashes them, producing an
    ASCII string :py:const:`.STRBYTES` long, including the null terminator.

    The returned string includes the salt and the tuning parameters,
    ``opslimit`` and ``memlimit``, and can be written directly to disk
    as a password hash

    :param passwd: bytes
    :param opslimit: int
    :param memlimit: int
    :rtype: bytestring
    """
    buf = ffi.new("unsigned char[]", STRBYTES)

    ret = lib.crypto_pwhash_scryptsalsa208sha256_str(buf, passwd,
                                                     len(passwd),
                                                     opslimit,
                                                     memlimit)

    if(ret != 0):
        raise CryptoError("Failed to hash password")

    return ffi.string(buf)


def crypto_pwhash_scryptsalsa208sha256_str_verify(passwd_hash, passwd):
    """
    Verifies the ``passwd`` against the ``passwd_hash`` that was generated.
    Returns True or False depending on the success

    :param passwd_hash: bytes
    :param passwd: bytes
    :rtype: boolean
    """

    if len(passwd_hash) != STRBYTES - 1:
        raise ValueError("Invalid password hash")

    if lib.crypto_pwhash_scryptsalsa208sha256_str_verify(passwd_hash,
                                                         passwd,
                                                         len(passwd)) == 0:
        return True
    else:
        return False
