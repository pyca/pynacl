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

import nacl.c
import nacl.encoding

AUTH_SIZE = nacl.c.crypto_onetimeauth_BYTES
KEY_SIZE = nacl.c.crypto_onetimeauth_KEYBYTES


def generate(message, key, encoder=nacl.encoding.RawEncoder):
    """
    Authenticates ``message`` using a secret ``key``, and returns an
    authenticator. All three are passed through the provided ``encoder``.

    :param message: bytes
    :param key: bytes
    :rtype: bytes
    """
    message = encoder.decode(message)
    key = encoder.decode(key)

    if len(key) != KEY_SIZE:
        raise ValueError("The key must be exactly %s bytes long" %
                         KEY_SIZE)

    authenticator = nacl.c.crypto_onetimeauth(message, key)

    return encoder.encode(authenticator)


def verify(authenticator, message, key, encoder=nacl.encoding.RawEncoder):
    """
    Check that ``authenticator`` is correct for ``message`` under the
    secret ``key`` and raise a ``BadSignatureError`` otherwise.

    :param authenticator: bytes
    :param message: bytes
    :param key: bytes
    :rtype: bool
    """

    authenticator = encoder.decode(authenticator)
    message = encoder.decode(message)
    key = encoder.decode(key)

    if len(authenticator) != AUTH_SIZE:
        raise ValueError("The authenticator must be exactly %s bytes long" %
                         AUTH_SIZE)

    if len(key) != KEY_SIZE:
        raise ValueError("The key must be exactly %s bytes long" %
                         KEY_SIZE)

    return nacl.c.crypto_onetimeauth_verify(authenticator, message, key)
