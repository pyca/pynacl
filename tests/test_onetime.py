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

import pytest

import nacl.encoding
import nacl.exceptions
import nacl.onetime


class TestOneTimeGenerate:

    def test_generate(self):
        a = nacl.onetime.generate(b"foo", b"1" * nacl.onetime.KEY_SIZE)
        assert len(a) == nacl.onetime.AUTH_SIZE

    @pytest.mark.parametrize("encoder", [
        nacl.encoding.HexEncoder,
        nacl.encoding.RawEncoder,
    ])
    def test_encoding(self, encoder):
        rawmsg = b"foo"
        rawkey = b"1" * nacl.onetime.KEY_SIZE

        encmsg = encoder.encode(rawmsg)
        enckey = encoder.encode(rawkey)

        a1 = nacl.onetime.generate(rawmsg, rawkey)
        a2 = nacl.onetime.generate(encmsg, enckey, encoder)

        assert a1 == encoder.decode(a2)

    def test_wrong_length(self):
        with pytest.raises(ValueError):
            nacl.onetime.generate(b"foo", b"1" * 31)


class TestOneTimeVerify:

    def test_verify(self):
        msg = b"foo"
        key = b"1" * nacl.onetime.KEY_SIZE

        a = nacl.onetime.generate(msg, key)
        assert len(a) == nacl.onetime.AUTH_SIZE

    @pytest.mark.parametrize("encoder", [
        nacl.encoding.HexEncoder,
        nacl.encoding.RawEncoder,
    ])
    def test_encoding(self, encoder):
        rawmsg = b"foo"
        rawkey = b"1" * nacl.onetime.KEY_SIZE

        encmsg = encoder.encode(rawmsg)
        enckey = encoder.encode(rawkey)

        a = nacl.onetime.generate(encmsg, enckey, encoder)
        assert nacl.onetime.verify(a, encmsg, enckey, encoder)

    @pytest.mark.parametrize(("msg", "key", "a"), [
        (
            # a was generated by tweet-nacl
            b'12e88ecb241226f24d298685de7ad2cc93ed745f',
            b'09f61ec34505cd0f4c9dddaa15cbae2e' \
            b'af234429991f2c12e41a5eee964819fa',
            b'd483cc10046057a315ae643f94c6c24c',
        )
    ])
    def test_positive_samples(self, msg, key, a):
        assert nacl.onetime.verify(a, msg, key, nacl.encoding.HexEncoder)

    @pytest.mark.parametrize(("msg", "key", "a"), [
        (
            # a was generated by tweet-nacl
            # corrupt msg
            b'A2e88ecb241226f24d298685de7ad2cc93ed745f',
            b'09f61ec34505cd0f4c9dddaa15cbae2e' \
            b'af234429991f2c12e41a5eee964819fa',
            b'd483cc10046057a315ae643f94c6c24c',
        ),
        (
            # a was generated by tweet-nacl
            # corrupt key
            b'12e88ecb241226f24d298685de7ad2cc93ed745f',
            b'A9f61ec34505cd0f4c9dddaa15cbae2e' \
            b'af234429991f2c12e41a5eee964819fa',
            b'd483cc10046057a315ae643f94c6c24c',
        ),
        (
            # a was generated by tweet-nacl
            # corrupt authenticator
            b'12e88ecb241226f24d298685de7ad2cc93ed745f',
            b'09f61ec34505cd0f4c9dddaa15cbae2e' \
            b'af234429991f2c12e41a5eee964819fa',
            b'A483cc10046057a315ae643f94c6c24c',
        )
    ])
    def test_negative_samples(self, msg, key, a):
        with pytest.raises(nacl.exceptions.BadSignatureError):
            nacl.onetime.verify(a, msg, key, nacl.encoding.HexEncoder)

    def test_wrong_auth_length(self):
        with pytest.raises(ValueError):
            nacl.onetime.verify(b"1" * (nacl.onetime.AUTH_SIZE + 1),
                                b"foo",
                                b"1" * nacl.onetime.KEY_SIZE)

    def test_wrong_key_length(self):
        with pytest.raises(ValueError):
            nacl.onetime.verify(b"1" * nacl.onetime.AUTH_SIZE,
                                b"foo",
                                b"1" * (nacl.onetime.KEY_SIZE - 1))