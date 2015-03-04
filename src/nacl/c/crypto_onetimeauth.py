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

from nacl._lib import lib
from nacl.exceptions import BadSignatureError, CryptoError

crypto_onetimeauth_BYTES = lib.crypto_onetimeauth_bytes()
crypto_onetimeauth_KEYBYTES = lib.crypto_onetimeauth_keybytes()


def crypto_onetimeauth(message, k):
    """
    Authenticates a ``message`` using a secret key ``k``, and returns an
    authenticator.

    :param message: bytes
    :param k: bytes
    :rtype: bytes
    """
    authenticator = lib.ffi.new("unsigned char[]", crypto_onetimeauth_BYTES)

    if lib.crypto_onetimeauth(authenticator, message, len(message), k) != 0:
        raise CryptoError("Failed to generate authenticator for message")

    return lib.ffi.buffer(authenticator, crypto_onetimeauth_BYTES)[:]


def crypto_onetimeauth_verify(authenticator, message, k):
    """
    Check that ``authenticator`` is correct for ``message`` under the
    secret ``k`` and raise a ``BadSignatureError`` otherwise.

    :param authenticator: bytes
    :param message: bytes
    :param k: bytes
    :rtype: bool
    """
    if lib.crypto_onetimeauth_verify(authenticator,
                                     message, len(message), k) != 0:
        raise BadSignatureError("Authenticator was forged or corrupt")

    return True
