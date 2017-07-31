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
from __future__ import absolute_import
from __future__ import division

import nacl.bindings
import nacl.encoding
import nacl.exceptions as exc

from nacl.exceptions import ensure

_strbytes_plus_one = nacl.bindings.crypto_pwhash_scryptsalsa208sha256_STRBYTES

SCRYPT_SALTBYTES = nacl.bindings.crypto_pwhash_scryptsalsa208sha256_SALTBYTES
SCRYPT_PWHASH_SIZE = _strbytes_plus_one - 1
SCRYPT_OPSLIMIT_INTERACTIVE = \
    nacl.bindings.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
SCRYPT_MEMLIMIT_INTERACTIVE = \
    nacl.bindings.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE
SCRYPT_OPSLIMIT_SENSITIVE = \
    nacl.bindings.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE
SCRYPT_MEMLIMIT_SENSITIVE = \
    nacl.bindings.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE

_argon2i_strbytes_plus_one = nacl.bindings.crypto_pwhash_argon2i_STRBYTES
ARGON2I_PWHASH_SIZE = _argon2i_strbytes_plus_one - 1
ARGON2I_SALTBYTES = nacl.bindings.crypto_pwhash_argon2i_SALTBYTES
ARGON2I_BYTES_MAX = \
    nacl.bindings.crypto_pwhash_argon2i_BYTES_MAX
ARGON2I_BYTES_MIN = \
    nacl.bindings.crypto_pwhash_argon2i_BYTES_MIN
ARGON2I_MEMLIMIT_MAX = \
    nacl.bindings.crypto_pwhash_argon2i_MEMLIMIT_MAX
ARGON2I_MEMLIMIT_MIN = \
    nacl.bindings.crypto_pwhash_argon2i_MEMLIMIT_MIN
ARGON2I_OPSLIMIT_MAX = \
    nacl.bindings.crypto_pwhash_argon2i_OPSLIMIT_MAX
ARGON2I_OPSLIMIT_MIN = \
    nacl.bindings.crypto_pwhash_argon2i_OPSLIMIT_MIN
ARGON2I_OPSLIMIT_INTERACTIVE = \
    nacl.bindings.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE
ARGON2I_MEMLIMIT_INTERACTIVE = \
    nacl.bindings.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE
ARGON2I_OPSLIMIT_MODERATE = \
    nacl.bindings.crypto_pwhash_argon2i_OPSLIMIT_MODERATE
ARGON2I_MEMLIMIT_MODERATE = \
    nacl.bindings.crypto_pwhash_argon2i_MEMLIMIT_MODERATE
ARGON2I_OPSLIMIT_SENSITIVE = \
    nacl.bindings.crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE
ARGON2I_MEMLIMIT_SENSITIVE = \
    nacl.bindings.crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE
ARGON2I_ALG13 = \
    nacl.bindings.crypto_pwhash_argon2i_ALG_ARGON2I13


def kdf_scryptsalsa208sha256(size, password, salt,
                             opslimit=SCRYPT_OPSLIMIT_SENSITIVE,
                             memlimit=SCRYPT_MEMLIMIT_SENSITIVE,
                             encoder=nacl.encoding.RawEncoder):
    """
    Makes a key defined from ``password`` and ``salt`` that is
    ``size`` bytes long

    the enclosing module provides the constants

        - :py:const:`.SCRYPT_OPSLIMIT_INTERACTIVE`
        - :py:const:`.SCRYPT_MEMLIMIT_INTERACTIVE`
        - :py:const:`.SCRYPT_OPSLIMIT_SENSITIVE`
        - :py:const:`.SCRYPT_MEMLIMIT_SENSITIVE`

    as a guidance for correct settings respectively for the
    interactive login and the long term key protecting sensitive data
    use cases.

    :param int size: int
    :param bytes password: bytes
    :param bytes salt: bytes
    :param int opslimit:
    :param int memlimit:
    :rtype: bytes
    """
    ensure(
        len(salt) == SCRYPT_SALTBYTES,
        "The salt must be exactly %s, not %s bytes long" % (
            SCRYPT_SALTBYTES,
            len(salt)
        ),
        raising=exc.ValueError
    )

    n_log2, r, p = nacl.bindings.nacl_bindings_pick_scrypt_params(opslimit,
                                                                  memlimit)
    maxmem = memlimit + (2 ** 16)

    return encoder.encode(
        nacl.bindings.crypto_pwhash_scryptsalsa208sha256_ll(
            password, salt, 2 ** n_log2, r, p, maxmem=maxmem, dklen=size)
    )


def scryptsalsa208sha256_str(password,
                             opslimit=SCRYPT_OPSLIMIT_INTERACTIVE,
                             memlimit=SCRYPT_MEMLIMIT_INTERACTIVE):
    """
    Hashes a password with a random salt, returning an ascii string
    that has all the needed info to check against a future password

    The default settings for opslimit and memlimit are those deemed
    correct for the interactive user login case.

    :param bytes password:
    :param int opslimit:
    :param int memlimit:
    :rtype: bytes
    """

    return nacl.bindings.crypto_pwhash_scryptsalsa208sha256_str(password,
                                                                opslimit,
                                                                memlimit)


def verify_scryptsalsa208sha256(password_hash, password):
    """
    Takes the output of scryptsalsa208sha256 and compares it against
    a user provided password to see if they are the same

    :param password_hash: bytes
    :param password: bytes
    :rtype: boolean
    """

    ensure(len(password_hash) == SCRYPT_PWHASH_SIZE,
           "The password hash must be exactly %s bytes long" %
           nacl.bindings.crypto_pwhash_scryptsalsa208sha256_STRBYTES,
           raising=exc.ValueError)

    return nacl.bindings.crypto_pwhash_scryptsalsa208sha256_str_verify(
        password_hash, password
    )


def kdf_argon2i(size, password, salt,
                opslimit=ARGON2I_OPSLIMIT_SENSITIVE,
                memlimit=ARGON2I_MEMLIMIT_SENSITIVE,
                encoder=nacl.encoding.RawEncoder,
                alg=ARGON2I_ALG13):
    """
    Derive a ``size`` bytes long key from a caller-supplied
    ``password`` and ``salt`` pair using the argon2i
    memory-hard construct.

    the enclosing module provides the constants

        - :py:const:`.ARGON2I_OPSLIMIT_INTERACTIVE`
        - :py:const:`.ARGON2I_MEMLIMIT_INTERACTIVE`
        - :py:const:`.ARGON2I_OPSLIMIT_MODERATE`
        - :py:const:`.ARGON2I_MEMLIMIT_MODERATE`
        - :py:const:`.ARGON2I_OPSLIMIT_SENSITIVE`
        - :py:const:`.ARGON2I_MEMLIMIT_SENSITIVE`

    as a guidance for correct settings.

    :param size: derived key size, must be comprised
                 between :py:const:`.ARGON2I_BYTES_MIN`
                 and :py:const:`.ARGON2I_BYTES_MAX`
    :type size: int
    :param password: password used to seed the key derivation procedure;
                     it maximum length is :py:const:`.ARGON2I_PASSWD_MAX`
    :type password: bytes
    :param salt: **RANDOM** salt used in the key derivation procedure;
                 its length must be exactly :py:const:`.ARGON2I_SALTBYTES`
    :type salt: bytes
    :param opslimit: the time component (operation count)
                     of the key derivation procedure's computational cost;
                     it must be comprised between
                     :py:const:`.ARGON2I_MIN_TIME`
                     and :py:const:`.ARGON2I_MAX_TIME`
    :type opslimit: int
    :param memlimit: the memory occupation component
                     of the key derivation procedure's computational cost;
                     it must be comprised between
                     :py:const:`.ARGON2I_MIN_MEMORY`
                     and :py:const:`.ARGON2I_MAX_MEMORY`
    :type memlimit: int
    :rtype: bytes

    .. versionadded:: 1.2
    """

    return encoder.encode(
        nacl.bindings.crypto_pwhash_argon2i(
            size, password, salt, opslimit, memlimit, alg)
    )


def argon2i_str(password,
                opslimit=ARGON2I_OPSLIMIT_INTERACTIVE,
                memlimit=ARGON2I_MEMLIMIT_INTERACTIVE):
    """
    Hashes a password with a random salt, returning an ascii string
    that has all the needed info to check against a future password

    The default settings for opslimit and memlimit are those deemed
    correct for the interactive user login case.

    :param bytes password:
    :param int opslimit:
    :param int memlimit:
    :rtype: bytes

    .. versionadded:: 1.2
    """

    return nacl.bindings.crypto_pwhash_argon2i_str(password,
                                                   opslimit,
                                                   memlimit)


def verify_argon2i(password_hash, password):
    """
    Takes the output from argon2i and compares it against
    a user provided password
    :param password_hash: password hash serialized in modular crypt() format
    :type password_hash: bytes
    :param password: user provided password
    :type password: bytes
    :rtype: boolean

    .. versionadded:: 1.2
    """
    return nacl.bindings.crypto_pwhash_argon2i_str_verify(password_hash,
                                                          password)
