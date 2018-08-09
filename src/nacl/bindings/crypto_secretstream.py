# Copyright 2013-2018 Donald Stufft and individual contributors
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

from nacl import exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure


crypto_secretstream_xchacha20poly1305_ABYTES = \
    lib.crypto_secretstream_xchacha20poly1305_abytes()
crypto_secretstream_xchacha20poly1305_HEADERBYTES = \
    lib.crypto_secretstream_xchacha20poly1305_headerbytes()
crypto_secretstream_xchacha20poly1305_KEYBYTES = \
    lib.crypto_secretstream_xchacha20poly1305_keybytes()
crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX = \
    lib.crypto_secretstream_xchacha20poly1305_messagebytes_max()
crypto_secretstream_xchacha20poly1305_STATEBYTES = \
    lib.crypto_secretstream_xchacha20poly1305_statebytes()


crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = \
    lib.crypto_secretstream_xchacha20poly1305_tag_message()
crypto_secretstream_xchacha20poly1305_TAG_PUSH = \
    lib.crypto_secretstream_xchacha20poly1305_tag_push()
crypto_secretstream_xchacha20poly1305_TAG_REKEY = \
    lib.crypto_secretstream_xchacha20poly1305_tag_rekey()
crypto_secretstream_xchacha20poly1305_TAG_FINAL = \
    lib.crypto_secretstream_xchacha20poly1305_tag_final()


def crypto_secretstream_xchacha20poly1305_keygen():
    """
    Generate a key for use with
    :func:`.crypto_secretstream_xchacha20poly1305_init_push`.

    """
    keybuf = ffi.new(
        "unsigned char[]",
        crypto_secretstream_xchacha20poly1305_KEYBYTES,
    )
    lib.crypto_secretstream_xchacha20poly1305_keygen(keybuf)
    return ffi.buffer(keybuf)[:]


def crypto_secretstream_xchacha20poly1305_init_push(key):
    """
    Initialize a crypto_secretstream_xchacha20poly1305 encryption buffer.

    :param key: must be
                :data:`.crypto_secretstream_xchacha20poly1305_KEYBYTES` long
    :type key: bytes
    :return: (state buffer, header)
    :rtype: (object, bytes)
    """
    ensure(
        isinstance(key, bytes),
        'Key must be a bytes sequence',
        raising=exc.TypeError,
    )
    ensure(
        len(key) == crypto_secretstream_xchacha20poly1305_KEYBYTES,
        'Invalid key length',
        raising=exc.ValueError,
    )

    statebuf = ffi.new(
        "unsigned char[]",
        crypto_secretstream_xchacha20poly1305_STATEBYTES,
    )

    headerbuf = ffi.new(
        "unsigned char []",
        crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    )

    rc = lib.crypto_secretstream_xchacha20poly1305_init_push(
        statebuf, headerbuf, key)
    ensure(rc == 0, 'Unexpected failure', raising=exc.RuntimeError)

    return statebuf, ffi.buffer(headerbuf)[:]


def crypto_secretstream_xchacha20poly1305_push(
    statebuf,
    m,
    ad=None,
    tag=crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
):
    """
    Add an encrypted message to the secret stream.

    :param statebuf: the initialized state buffer returned from
                     :func:`.crypto_secretstream_xchacha20poly1305_init_push`.
    :type statebuf: object
    :param m: the message to encrypt, the maximum length of an individual
              message is
              :data:`.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX`.
    :type m: bytes
    :param ad: additional data to include in the authentication tag
    :type ad: bytes or None
    :param tag: the message tag, usually
                :data:`.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE` or
                :data:`.crypto_secretstream_xchacha20poly1305_TAG_FINAL`.
    :type tag: int
    :return: ciphertext
    :rtype: bytes
    """
    ensure(isinstance(m, bytes), 'Message is not bytes', raising=exc.TypeError)
    ensure(
        len(m) <= crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX,
        'Message is too long',
        raising=exc.ValueError,
    )
    ensure(
        ad is None or isinstance(ad, bytes),
        'Additional data must be bytes or None',
        raising=exc.TypeError,
    )

    clen = len(m) + crypto_secretstream_xchacha20poly1305_ABYTES
    cbuf = ffi.new('unsigned char[]', clen)
    if ad is None:
        ad = ffi.NULL
        adlen = 0
    else:
        adlen = len(ad)

    rc = lib.crypto_secretstream_xchacha20poly1305_push(
        statebuf,
        cbuf, ffi.NULL,
        m, len(m),
        ad, adlen,
        tag,
    )
    ensure(rc == 0, 'Unexpected failure', raising=exc.RuntimeError)

    return ffi.buffer(cbuf)[:]


def crypto_secretstream_xchacha20poly1305_init_pull(header, key):
    """
    Initialize a crypto_secretstream_xchacha20poly1305 decryption buffer.

    :param header: must be
                :data:`.crypto_secretstream_xchacha20poly1305_HEADERBYTES` long
    :type header: bytes
    :param key: must be
                :data:`.crypto_secretstream_xchacha20poly1305_KEYBYTES` long
    :type key: bytes
    :return: initialized state buffer
    :rtype: object
    """
    ensure(
        isinstance(header, bytes),
        'Header must be a bytes sequence',
        raising=exc.TypeError,
    )
    ensure(
        len(header) == crypto_secretstream_xchacha20poly1305_HEADERBYTES,
        'Invalid header length',
        raising=exc.ValueError,
    )
    ensure(
        isinstance(key, bytes),
        'Key must be a bytes sequence',
        raising=exc.TypeError,
    )
    ensure(
        len(key) == crypto_secretstream_xchacha20poly1305_KEYBYTES,
        'Invalid key length',
        raising=exc.ValueError,
    )

    statebuf = ffi.new(
        "unsigned char[]",
        crypto_secretstream_xchacha20poly1305_STATEBYTES,
    )

    rc = lib.crypto_secretstream_xchacha20poly1305_init_pull(
        statebuf, header, key)
    ensure(rc == 0, 'Unexpected failure', raising=exc.RuntimeError)

    return statebuf


def crypto_secretstream_xchacha20poly1305_pull(statebuf, c, ad=None):
    """
    Read a decrypted message from the secret stream.

    :param statebuf: the initialized state buffer returned from
                     :func:`.crypto_secretstream_xchacha20poly1305_init_pull`.
    :type statebuf: object
    :param c: the ciphertext to decrypt, the maximum length of an individual
              ciphertext is
              :data:`.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX` +
              :data:`.crypto_secretstream_xchacha20poly1305_ABYTES`.
    :type c: bytes
    :param ad: additional data to include in the authentication tag
    :type ad: bytes or None
    :return: (message, tag)
    :rtype: (bytes, int)
    """
    ensure(
        isinstance(c, bytes),
        'Ciphertext is not bytes',
        raising=exc.TypeError,
    )
    ensure(
        len(c) > crypto_secretstream_xchacha20poly1305_ABYTES,
        'Ciphertext is too short',
        raising=exc.ValueError,
    )
    ensure(
        len(c) <= (
            crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX +
            crypto_secretstream_xchacha20poly1305_ABYTES
        ),
        'Ciphertext is too long',
        raising=exc.ValueError,
    )
    ensure(
        ad is None or isinstance(ad, bytes),
        'Additional data must be bytes or None',
        raising=exc.TypeError,
    )

    mlen = len(c) - crypto_secretstream_xchacha20poly1305_ABYTES
    mbuf = ffi.new('unsigned char[]', mlen)
    tag_p = ffi.new('unsigned char *')
    if ad is None:
        ad = ffi.NULL
        adlen = 0
    else:
        adlen = len(ad)

    rc = lib.crypto_secretstream_xchacha20poly1305_pull(
        statebuf,
        mbuf, ffi.NULL, tag_p,
        c, len(c),
        ad, adlen,
    )
    ensure(rc == 0, 'Unexpected failure', raising=exc.RuntimeError)

    return (ffi.buffer(mbuf)[:], tag_p[0])


def crypto_secretstream_xchacha20poly1305_rekey(statebuf):
    """
    Explicitly change the encryption key in the stream.

    Normally the stream is re-keyed as needed or an explicit ``tag`` of
    :data:`.crypto_secretstream_xchacha20poly1305_TAG_REKEY` is added to a
    message to ensure forward secrecy, but this method can be used instead
    if the re-keying is controlled without adding the tag.

    :param statebuf: the initialized state buffer returned from
                     :func:`.crypto_secretstream_xchacha20poly1305_init_push`
                     or
                     :func:`.crypto_secretstream_xchacha20poly1305_init_pull`.
    :type statebuf: object
    """
    lib.crypto_secretstream_xchacha20poly1305_rekey(statebuf)
