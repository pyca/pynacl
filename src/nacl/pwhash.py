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

from nacl.utils import Constants


_strbytes_plus_one = nacl.bindings.crypto_pwhash_scryptsalsa208sha256_STRBYTES


class SCRYPT(Constants):
    """
    Constants needed for scrypt password hasher usage
    """
    SALTBYTES = nacl.bindings.crypto_pwhash_scryptsalsa208sha256_SALTBYTES
    PWHASH_SIZE = _strbytes_plus_one - 1
    OPSLIMIT_INTERACTIVE = \
        nacl.bindings.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
    MEMLIMIT_INTERACTIVE = \
        nacl.bindings.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE
    OPSLIMIT_SENSITIVE = \
        nacl.bindings.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE
    MEMLIMIT_SENSITIVE = \
        nacl.bindings.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE


SCRYPT_SALTBYTES = SCRYPT.SALTBYTES
SCRYPT_PWHASH_SIZE = SCRYPT.PWHASH_SIZE
SCRYPT_OPSLIMIT_INTERACTIVE = SCRYPT.OPSLIMIT_INTERACTIVE
SCRYPT_MEMLIMIT_INTERACTIVE = SCRYPT.MEMLIMIT_INTERACTIVE
SCRYPT_OPSLIMIT_SENSITIVE = SCRYPT.OPSLIMIT_SENSITIVE
SCRYPT_MEMLIMIT_SENSITIVE = SCRYPT.MEMLIMIT_SENSITIVE


_argon2_strbytes_plus_one = nacl.bindings.crypto_pwhash_STRBYTES


class ARGON2I(Constants):
    PWHASH_SIZE = _argon2_strbytes_plus_one - 1
    SALTBYTES = nacl.bindings.crypto_pwhash_SALTBYTES
    BYTES_MAX = nacl.bindings.crypto_pwhash_BYTES_MAX
    BYTES_MIN = nacl.bindings.crypto_pwhash_BYTES_MIN
    MEMLIMIT_MAX = nacl.bindings.crypto_pwhash_argon2i_MEMLIMIT_MAX
    MEMLIMIT_MIN = nacl.bindings.crypto_pwhash_argon2i_MEMLIMIT_MIN
    OPSLIMIT_MAX = nacl.bindings.crypto_pwhash_argon2i_OPSLIMIT_MAX
    OPSLIMIT_MIN = nacl.bindings.crypto_pwhash_argon2i_OPSLIMIT_MIN
    OPSLIMIT_INTERACTIVE = \
        nacl.bindings.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE
    MEMLIMIT_INTERACTIVE = \
        nacl.bindings.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE
    OPSLIMIT_MODERATE = \
        nacl.bindings.crypto_pwhash_argon2i_OPSLIMIT_MODERATE
    MEMLIMIT_MODERATE = \
        nacl.bindings.crypto_pwhash_argon2i_MEMLIMIT_MODERATE
    OPSLIMIT_SENSITIVE = \
        nacl.bindings.crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE
    MEMLIMIT_SENSITIVE = \
        nacl.bindings.crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE
    ALG = nacl.bindings.crypto_pwhash_ALG_ARGON2I13


class ARGON2ID(Constants):
    PWHASH_SIZE = _argon2_strbytes_plus_one - 1
    SALTBYTES = nacl.bindings.crypto_pwhash_SALTBYTES
    BYTES_MAX = nacl.bindings.crypto_pwhash_BYTES_MAX
    BYTES_MIN = nacl.bindings.crypto_pwhash_BYTES_MIN
    MEMLIMIT_MIN = nacl.bindings.crypto_pwhash_argon2id_MEMLIMIT_MIN
    MEMLIMIT_MAX = nacl.bindings.crypto_pwhash_argon2id_MEMLIMIT_MAX
    OPSLIMIT_MIN = nacl.bindings.crypto_pwhash_argon2id_OPSLIMIT_MIN
    OPSLIMIT_MAX = nacl.bindings.crypto_pwhash_argon2id_OPSLIMIT_MAX
    OPSLIMIT_INTERACTIVE = \
        nacl.bindings.crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE
    MEMLIMIT_INTERACTIVE = \
        nacl.bindings.crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE
    OPSLIMIT_MODERATE = \
        nacl.bindings.crypto_pwhash_argon2id_OPSLIMIT_MODERATE
    MEMLIMIT_MODERATE = \
        nacl.bindings.crypto_pwhash_argon2id_MEMLIMIT_MODERATE
    OPSLIMIT_SENSITIVE = \
        nacl.bindings.crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE
    MEMLIMIT_SENSITIVE = \
        nacl.bindings.crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE
    ALG = nacl.bindings.crypto_pwhash_ALG_ARGON2ID13


def kdf_scryptsalsa208sha256(size, password, salt,
                             opslimit=SCRYPT.OPSLIMIT_SENSITIVE,
                             memlimit=SCRYPT.MEMLIMIT_SENSITIVE,
                             encoder=nacl.encoding.RawEncoder):
    """
    Makes a key defined from ``password`` and ``salt`` that is
    ``size`` bytes long

    the enclosing module provides the constants

        - :py:const:`.SCRYPT.OPSLIMIT_INTERACTIVE`
        - :py:const:`.SCRYPT.MEMLIMIT_INTERACTIVE`
        - :py:const:`.SCRYPT.OPSLIMIT_SENSITIVE`
        - :py:const:`.SCRYPT.MEMLIMIT_SENSITIVE`

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
        len(salt) == SCRYPT.SALTBYTES,
        "The salt must be exactly %s, not %s bytes long" % (
            SCRYPT.SALTBYTES,
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
                             opslimit=SCRYPT.OPSLIMIT_INTERACTIVE,
                             memlimit=SCRYPT.MEMLIMIT_INTERACTIVE):
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

    ensure(len(password_hash) == SCRYPT.PWHASH_SIZE,
           "The password hash must be exactly %s bytes long" %
           nacl.bindings.crypto_pwhash_scryptsalsa208sha256_STRBYTES,
           raising=exc.ValueError)

    return nacl.bindings.crypto_pwhash_scryptsalsa208sha256_str_verify(
        password_hash, password
    )


def kdf_argon2i(size, password, salt,
                opslimit=ARGON2I.OPSLIMIT_SENSITIVE,
                memlimit=ARGON2I.MEMLIMIT_SENSITIVE,
                encoder=nacl.encoding.RawEncoder):
    """
    Derive a ``size`` bytes long key from a caller-supplied
    ``password`` and ``salt`` pair using the argon2i
    memory-hard construct.

    the enclosing module provides the constants

        - :py:const:`.ARGON2I.OPSLIMIT_INTERACTIVE`
        - :py:const:`.ARGON2I.MEMLIMIT_INTERACTIVE`
        - :py:const:`.ARGON2I.OPSLIMIT_MODERATE`
        - :py:const:`.ARGON2I.MEMLIMIT_MODERATE`
        - :py:const:`.ARGON2I.OPSLIMIT_SENSITIVE`
        - :py:const:`.ARGON2I.MEMLIMIT_SENSITIVE`

    as a guidance for correct settings.

    :param size: derived key size, must be comprised
                 between :py:const:`.ARGON2I.BYTES_MIN`
                 and :py:const:`.ARGON2I.BYTES_MAX`
    :type size: int
    :param password: password used to seed the key derivation procedure;
                     it maximum length is :py:const:`.ARGON2I.PASSWD_MAX`
    :type password: bytes
    :param salt: **RANDOM** salt used in the key derivation procedure;
                 its length must be exactly :py:const:`.ARGON2I.SALTBYTES`
    :type salt: bytes
    :param opslimit: the time component (operation count)
                     of the key derivation procedure's computational cost;
                     it must be comprised between
                     :py:const:`.ARGON2I.MIN_TIME`
                     and :py:const:`.ARGON2I.MAX_TIME`
    :type opslimit: int
    :param memlimit: the memory occupation component
                     of the key derivation procedure's computational cost;
                     it must be comprised between
                     :py:const:`.ARGON2I.MIN_MEMORY`
                     and :py:const:`.ARGON2I.MAX_MEMORY`
    :type memlimit: int
    :rtype: bytes

    .. versionadded:: 1.2
    """

    return encoder.encode(
        nacl.bindings.crypto_pwhash_alg(size, password, salt,
                                        opslimit, memlimit,
                                        ARGON2I.ALG)
    )


def kdf_argon2id(size, password, salt,
                 opslimit=ARGON2ID.OPSLIMIT_SENSITIVE,
                 memlimit=ARGON2ID.MEMLIMIT_SENSITIVE,
                 encoder=nacl.encoding.RawEncoder):
    """
    Derive a ``size`` bytes long key from a caller-supplied
    ``password`` and ``salt`` pair using the partially data dependent
    ``argon2id`` memory-hard construct.

    the enclosing module provides the constants

        - :py:const:`.ARGON2ID.OPSLIMIT_INTERACTIVE`
        - :py:const:`.ARGON2ID.MEMLIMIT_INTERACTIVE`
        - :py:const:`.ARGON2ID.OPSLIMIT_MODERATE`
        - :py:const:`.ARGON2ID.MEMLIMIT_MODERATE`
        - :py:const:`.ARGON2ID.OPSLIMIT_SENSITIVE`
        - :py:const:`.ARGON2ID.MEMLIMIT_SENSITIVE`

    as a guidance for correct settings.

    :param size: derived key size, must be comprised
                 between :py:const:`.ARGON2ID.BYTES_MIN`
                 and :py:const:`.ARGON2ID.BYTES_MAX`
    :type size: int
    :param password: password used to seed the key derivation procedure;
                     it maximum length is :py:const:`.ARGON2ID.PASSWD_MAX`
    :type password: bytes
    :param salt: **RANDOM** salt used in the key derivation procedure;
                 its length must be exactly :py:const:`.ARGON2ID.SALTBYTES`
    :type salt: bytes
    :param opslimit: the time component (operation count)
                     of the key derivation procedure's computational cost;
                     it must be comprised between
                     :py:const:`.ARGON2ID.MIN_TIME`
                     and :py:const:`.ARGON2ID.MAX_TIME`
    :type opslimit: int
    :param memlimit: the memory occupation component
                     of the key derivation procedure's computational cost;
                     it must be comprised between
                     :py:const:`.ARGON2ID.MIN_MEMORY`
                     and :py:const:`.ARGON2ID.MAX_MEMORY`
    :type memlimit: int
    :rtype: bytes

    .. versionadded:: 1.2
    """

    return encoder.encode(
        nacl.bindings.crypto_pwhash_alg(size, password, salt,
                                        opslimit, memlimit,
                                        ARGON2ID.ALG)
    )


def argon2i_str(password,
                opslimit=ARGON2I.OPSLIMIT_INTERACTIVE,
                memlimit=ARGON2I.MEMLIMIT_INTERACTIVE):
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
    return nacl.bindings.crypto_pwhash_str_alg(password,
                                               opslimit,
                                               memlimit,
                                               ARGON2I.ALG)


def argon2id_str(password,
                 opslimit=ARGON2ID.OPSLIMIT_INTERACTIVE,
                 memlimit=ARGON2ID.MEMLIMIT_INTERACTIVE):
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

    return nacl.bindings.crypto_pwhash_str_alg(password,
                                               opslimit,
                                               memlimit,
                                               ARGON2ID.ALG)


def verify_argon2(password_hash, password):
    """
    Takes a modular crypt encoded argon2i or argon2id stored password hash
    and checks if the user provided password will hash to the same string
    when using the stored parameters

    :param password_hash: password hash serialized in modular crypt() format
    :type password_hash: bytes
    :param password: user provided password
    :type password: bytes
    :rtype: boolean

    .. versionadded:: 1.2
    """
    return nacl.bindings.crypto_pwhash_str_verify(password_hash,
                                                  password)


verify_argon2i = verify_argon2
