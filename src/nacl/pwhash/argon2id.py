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

from . import argon2

BYTES_MIN = argon2.BYTES_MIN
BYTES_MAX = argon2.BYTES_MAX
PWHASH_SIZE = argon2.PWHASH_SIZE
SALTBYTES = argon2.SALTBYTES
ALG = argon2.ALG_ARGON2ID13

verify = argon2.verify

MEMLIMIT_MIN = \
    nacl.bindings.crypto_pwhash_argon2id_MEMLIMIT_MIN
MEMLIMIT_MAX = \
    nacl.bindings.crypto_pwhash_argon2id_MEMLIMIT_MAX
OPSLIMIT_MIN = \
    nacl.bindings.crypto_pwhash_argon2id_OPSLIMIT_MIN
OPSLIMIT_MAX = \
    nacl.bindings.crypto_pwhash_argon2id_OPSLIMIT_MAX
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


def kdf(size, password, salt,
        opslimit=OPSLIMIT_SENSITIVE,
        memlimit=MEMLIMIT_SENSITIVE,
        encoder=nacl.encoding.RawEncoder):
    """
    Derive a ``size`` bytes long key from a caller-supplied
    ``password`` and ``salt`` pair using the argon2i
    memory-hard construct.

    the enclosing module provides the constants

        - :py:const:`.OPSLIMIT_INTERACTIVE`
        - :py:const:`.MEMLIMIT_INTERACTIVE`
        - :py:const:`.OPSLIMIT_MODERATE`
        - :py:const:`.MEMLIMIT_MODERATE`
        - :py:const:`.OPSLIMIT_SENSITIVE`
        - :py:const:`.MEMLIMIT_SENSITIVE`

    as a guidance for correct settings.

    :param size: derived key size, must be between
                 :py:const:`.BYTES_MIN` and
                 :py:const:`.BYTES_MAX`
    :type size: int
    :param password: password used to seed the key derivation procedure;
                     it maximum length is :py:const:`.PASSWD_MAX`
    :type password: bytes
    :param salt: **RANDOM** salt used in the key derivation procedure;
                 its length must be exactly :py:const:`.SALTBYTES`
    :type salt: bytes
    :param opslimit: the time component (operation count)
                     of the key derivation procedure's computational cost;
                     it must be between
                     :py:const:`.MIN_TIME` and
                     :py:const:`.MAX_TIME`
    :type opslimit: int
    :param memlimit: the memory occupation component
                     of the key derivation procedure's computational cost;
                     it must be between
                     :py:const:`.MIN_MEMORY` and
                     :py:const:`.MAX_MEMORY`
    :type memlimit: int
    :rtype: bytes

    .. versionadded:: 1.2
    """

    return encoder.encode(
        nacl.bindings.crypto_pwhash_alg(size, password, salt,
                                        opslimit, memlimit,
                                        ALG)
    )


def str(password,
        opslimit=OPSLIMIT_INTERACTIVE,
        memlimit=MEMLIMIT_INTERACTIVE):
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
                                               ALG)
