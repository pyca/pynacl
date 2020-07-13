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

import binascii

import pytest

from nacl.bindings.crypto_stream import (
    crypto_stream_chacha20,
    crypto_stream_chacha20_ietf,
    crypto_stream_chacha20_ietf_keygen,
    crypto_stream_chacha20_ietf_xor,
    crypto_stream_chacha20_ietf_xor_ic,
    crypto_stream_chacha20_keygen,
    crypto_stream_chacha20_xor,
    crypto_stream_chacha20_xor_ic,
    crypto_stream_xchacha20,
    crypto_stream_xchacha20_KEYBYTES,
    crypto_stream_xchacha20_NONCEBYTES,
    crypto_stream_xchacha20_keygen,
    crypto_stream_xchacha20_xor,
    crypto_stream_xchacha20_xor_ic,
    has_crypto_stream_xchacha20
)
from nacl.exceptions import UnavailableError
from nacl.utils import random as randombytes


def sodium_is_zero(data):
    d = 0
    for x in data:
        if isinstance(x, str):
            x = ord(x)
        d |= x
    return 1 & ((d - 1) >> 8)


def test_stream_chacha20():
    vectors = [
        {"key":
            "0000000000000000000000000000000000000000000000000000000000000000",
         "nonce": "0000000000000000"},
        {"key":
            "0000000000000000000000000000000000000000000000000000000000000001",
         "nonce": "0000000000000000"},
        {"key":
            "0000000000000000000000000000000000000000000000000000000000000000",
         "nonce": "0000000000000001"},
        {"key":
            "0000000000000000000000000000000000000000000000000000000000000000",
         "nonce": "0100000000000000"},
        {"key":
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "nonce": "0001020304050607"}
    ]

    final_outs = [
        (b"b5dae3cbb3d7a42bc0521db92649f5373d15dfe15440bed1ae43ee14ba18818376"
         b"e616393179040372008b06420b552b4791fc1ba85e11b31b54571e69aa66587a42"
         b"c9d864fe77d65c6606553ec89c24cb9cd7640bc49b1acbb922aa046b8bffd81889"
         b"5e835afc147cfbf1e6e630ba6c4be5a53a0b69146cb5514cca9da27385dffb96b5"
         b"85eadb5759d8051270f47d81c7661da216a19f18d5e7b734bc440267"),
        (b"424242424242424242424242424242424242424242424242424242424242424242"
         b"424242424242424242424242424242424242424242424242424242424242424242"
         b"424242424242424242424242424242424242424242424242424242424242424242"
         b"424242424242424242424242424242424242424242424242424242424242424242"
         b"42424242424242424242424242424242424242424242424242424242"),
        (b"7a42c9d864fe77d65c6606553ec89c24cb9cd7640bc49b1acbb922aa046b8bffd8"
         b"18895e835afc147cfbf1e6e630ba6c4be5a53a0b69146cb5514cca9da27385dffb"
         b"96b585eadb5759d8051270f47d81c7661da216a19f18d5e7b734bc440267918c46"
         b"6e1428f08745f37a99c77c7f2b1b244bd4162e8b86e4a8bf85358202954ced04b5"
         b"2fef7b3ba787744e715554285ecb0ed6e133c528d69d346abc0ce8b0"),
    ]

    out_len = 160
    zero = b'\x00' * out_len

    key = bytes()
    nonce = bytes()

    for vec in vectors:
        key = binascii.unhexlify(vec['key'])
        nonce = binascii.unhexlify(vec['nonce'])

        out = crypto_stream_chacha20(out_len, nonce, key)
        out2 = crypto_stream_chacha20_xor(out, nonce, key)
        assert out2 == zero

    out = crypto_stream_chacha20(0, nonce, key)
    out = crypto_stream_chacha20_xor(out, nonce, key)
    out = crypto_stream_chacha20_xor(out, nonce, key)
    out = crypto_stream_chacha20_xor_ic(out, nonce, 1, key)

    out = b'\x42' * out_len
    out = crypto_stream_chacha20_xor(out, nonce, key)
    expected = binascii.unhexlify(final_outs[0])
    assert expected == out

    out = crypto_stream_chacha20_xor_ic(out, nonce, 0, key)
    expected = binascii.unhexlify(final_outs[1])
    assert expected == out

    out = crypto_stream_chacha20_xor_ic(out, nonce, 1, key)
    expected = binascii.unhexlify(final_outs[2])
    assert expected == out

    assert not sodium_is_zero(crypto_stream_chacha20_keygen())


def test_stream_chacha20_ietf():
    vectors = [
        {"key":
            "0000000000000000000000000000000000000000000000000000000000000000",
         "nonce": "000000000000000000000000",
         "ic": 0},
        {"key":
            "0000000000000000000000000000000000000000000000000000000000000000",
         "nonce": "000000000000000000000000",
         "ic": 1},
        {"key":
            "0000000000000000000000000000000000000000000000000000000000000001",
         "nonce": "000000000000000000000000",
         "ic": 1},
        {"key":
            "00ff000000000000000000000000000000000000000000000000000000000000",
         "nonce": "000000000000000000000000",
         "ic": 2},
        {"key":
            "0000000000000000000000000000000000000000000000000000000000000000",
         "nonce": "000000000000000000000002",
         "ic": 0},
        {"key":
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "nonce": "000000090000004a00000000",
         "ic": 1},
        {"key":
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "nonce": "000000090000004a00000000",
         "ic": 0xfeffffff}
    ]

    final_outs = [
        (b"c89ed3bfddb6b2b7594def12bd579475a64cbfe0448e1085c1e50042127e57c08f"
         b"da71743f4816973f7edcdbcd0b4ca4dee10e5dbbab7be517c6876f2b48779652b3"
         b"a5a693791b57124d9f5de16233868593b68571822a414660e8d881962e0c90c026"
         b"0445dde84b568095479bc940e0f750de939c540cfb8992c1aae0127e0c48cac135"
         b"7b95fd0cba8eeef2a869fb94df1481d6e8775fbfe7fd07dd486cddaa"),
        (b"424242424242424242424242424242424242424242424242424242424242424242"
         b"424242424242424242424242424242424242424242424242424242424242424242"
         b"424242424242424242424242424242424242424242424242424242424242424242"
         b"424242424242424242424242424242424242424242424242424242424242424242"
         b"42424242424242424242424242424242424242424242424242424242"),
        (b"52b3a5a693791b57124d9f5de16233868593b68571822a414660e8d881962e0c90"
         b"c0260445dde84b568095479bc940e0f750de939c540cfb8992c1aae0127e0c48ca"
         b"c1357b95fd0cba8eeef2a869fb94df1481d6e8775fbfe7fd07dd486cddaaa563ba"
         b"d017bb86c4fd6325de2a7f0dde1eb0b865c4176442194488750ec4ed799efdff89"
         b"c1fc27c46c97804cec1801665f28d0982f88d85729a010d5b75e655a"),
    ]

    out_len = 160
    zero = b'\x00' * out_len

    key = bytes()
    nonce = bytes()

    for vec in vectors:
        key = binascii.unhexlify(vec['key'])
        nonce = binascii.unhexlify(vec['nonce'])

        out = crypto_stream_chacha20_ietf(out_len, nonce, key)
        out2 = crypto_stream_chacha20_ietf_xor(out, nonce, key)
        assert out2 == zero

    out = crypto_stream_chacha20_ietf(0, nonce, key)
    out = crypto_stream_chacha20_ietf_xor(out, nonce, key)
    out = crypto_stream_chacha20_ietf_xor(out, nonce, key)
    out = crypto_stream_chacha20_ietf_xor_ic(out, nonce, 1, key)

    out = b'\x42' * out_len
    out = crypto_stream_chacha20_ietf_xor(out, nonce, key)
    expected = binascii.unhexlify(final_outs[0])
    assert expected == out

    out = crypto_stream_chacha20_ietf_xor_ic(out, nonce, 0, key)
    expected = binascii.unhexlify(final_outs[1])
    assert expected == out

    out = crypto_stream_chacha20_ietf_xor_ic(out, nonce, 1, key)
    expected = binascii.unhexlify(final_outs[2])
    assert expected == out

    assert not sodium_is_zero(crypto_stream_chacha20_ietf_keygen())


@pytest.mark.skipif(not has_crypto_stream_xchacha20,
                    reason='Requires full build of libsodium')
def test_stream_xchacha20():
    vectors = [
        {"key": (b"79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24"
                 b"f304fc4"),
         "nonce": b"b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419",
         "out": b"c6e9758160083ac604ef90e712ce6e75d7797590744e0cf060f013739c"},
        {"key": (b"ddf7784fee099612c40700862189d0397fcc4cc4b3cc02b5456b3a97d"
                 b"1186173"),
         "nonce": b"a9a04491e7bf00c3ca91ac7c2d38a777d88993a7047dfcc4",
         "out": b"2f289d371f6f0abc3cb60d11d9b7b29adf6bc5ad843e8493e928448d"},
        {"key": (b"3d12800e7b014e88d68a73f0a95b04b435719936feba60473f02a9e61"
                 b"ae60682"),
         "nonce": b"56bed2599eac99fb27ebf4ffcb770a64772dec4d5849ea2d",
         "out": b"a2c3c1406f33c054a92760a8e0666b84f84fa3a618f0"},
        {"key": (b"5f5763ff9a30c95da5c9f2a8dfd7cc6efd9dfb431812c075aa3e4f32e"
                 b"04f53e4"),
         "nonce": b"a5fa890efa3b9a034d377926ce0e08ee6d7faccaee41b771",
         "out": (b"8a1a5ba898bdbcff602b1036e469a18a5e45789d0e8d9837d81a2388a"
                 b"52b0b6a0f51891528f424c4a7f492a8dd7bce8bac19fbdbe1fb379ac0")
         },
        {"key": (b"eadc0e27f77113b5241f8ca9d6f9a5e7f09eee68d8a5cf30700563bf0"
                 b"1060b4e"),
         "nonce": b"a171a4ef3fde7c4794c5b86170dc5a099b478f1b852f7b64",
         "out": (b"23839f61795c3cdbcee2c749a92543baeeea3cbb721402aa42e6cae14"
                 b"0447575f2916c5d71108e3b13357eaf86f060cb")},
        {"key": (b"91319c9545c7c804ba6b712e22294c386fe31c4ff3d278827637b959d"
                 b"3dbaab2"),
         "nonce": b"410e854b2a911f174aaf1a56540fc3855851f41c65967a4e",
         "out": (b"cbe7d24177119b7fdfa8b06ee04dade4256ba7d35ffda6b89f014e479"
                 b"faef6")},
        {"key": (b"6a6d3f412fc86c4450fc31f89f64ed46baa3256ffcf8616e8c23a06c4"
                 b"22842b6"),
         "nonce": b"6b7773fce3c2546a5db4829f53a9165f41b08faae2fb72d5",
         "out": (b"8b23e35b3cdd5f3f75525fc37960ec2b68918e8c046d8a832b9838f15"
                 b"46be662e54feb1203e2")},
        {"key": (b"d45e56368ebc7ba9be7c55cfd2da0feb633c1d86cab67cd5627514fd2"
                 b"0c2b391"),
         "nonce": b"fd37da2db31e0c738754463edadc7dafb0833bd45da497fc",
         "out": (b"47950efa8217e3dec437454bd6b6a80a287e2570f0a48b3fa1ea3eb86"
                 b"8be3d486f6516606d85e5643becc473b370871ab9ef8e2a728f73b92b"
                 b"d98e6e26ea7c8ff96ec5a9e8de95e1eee9300c")},
        {"key": (b"aface41a64a9a40cbc604d42bd363523bd762eb717f3e08fe2e0b4611"
                 b"eb4dcf3"),
         "nonce": b"6906e0383b895ab9f1cf3803f42f27c79ad47b681c552c63",
         "out": (b"a5fa7c0190792ee17675d52ad7570f1fb0892239c76d6e802c26b5b35"
                  b"44d13151e67513b8aaa1ac5af2d7fd0d5e4216964324838")},
        {"key": (b"9d23bd4149cb979ccf3c5c94dd217e9808cb0e50cd0f67812235eaaf6"
                 b"01d6232"),
         "nonce": b"c047548266b7c370d33566a2425cbf30d82d1eaf5294109e",
         "out": (b"a21209096594de8c5667b1d13ad93f744106d054df210e4782cd396fe"
                 b"c692d3515a20bf351eec011a92c367888bc464c32f0807acd6c203a24"
                 b"7e0db854148468e9f96bee4cf718d68d5f637cbd5a376457788e6fae9"
                 b"0fc31097cfc")},
    ]

    final_out = (b"3e34c160a966ddfbd52d38f6a440a77256c1134ad54653db427dfdfc72"
                 b"f0f995768039052ec2ec4e6fe02c655d7d95681fabd417c087ad17f177"
                 b"510ba09d4cfe7beb8f7c9b8330d746310f9e29583e9ef240156015faaf"
                 b"eb24a4d002d6337b7bcec8b54a64ef704e1ae3247d79625d267cbacd1c"
                 b"90e4a2df2f72d4090babf88c90e65a086c464ec1753c49d3b8ad02f2a3"
                 b"c0808e1695c5d77cec6f6f12578ae4ed077a2046e06644d14af65ae90f"
                 b"2869a6f1f910b83a7a3cfec8dd390621a511")
    final_out = binascii.unhexlify(final_out)

    key = bytes()
    nonce = bytes()
    out = bytes()

    for vec in vectors:
        key = binascii.unhexlify(vec["key"])
        nonce = binascii.unhexlify(vec["nonce"])
        out = binascii.unhexlify(vec["out"])

        out2 = crypto_stream_xchacha20(len(out), nonce, key)
        assert out == out2

        out2 = crypto_stream_xchacha20_xor(out, nonce, key)
        assert sodium_is_zero(out2)

        out2 = crypto_stream_xchacha20_xor_ic(out, nonce, 0, key)
        assert sodium_is_zero(out2)

        out2 = crypto_stream_xchacha20_xor_ic(out, nonce, 1, key)
        assert not sodium_is_zero(out2)

        out = crypto_stream_xchacha20_xor(out, nonce, key)
        assert sodium_is_zero(out)

    out2 = crypto_stream_xchacha20(0, nonce, key)
    out2 = crypto_stream_xchacha20_xor(out2, nonce, key)
    out2 = crypto_stream_xchacha20_xor_ic(out2, nonce, 1, key)

    out = randombytes(64)
    out2 = randombytes(64)
    out2 += out

    out = crypto_stream_xchacha20_xor_ic(out, nonce, 1, key)
    out2 = crypto_stream_xchacha20_xor(out2, nonce, key)
    assert out == out2[64:]

    out = b'\x00' * 192
    out2 = b'\x00' * 192

    out2 = crypto_stream_xchacha20_xor_ic(out2, nonce, (1 << 32) - 1, key)
    out3 = crypto_stream_xchacha20_xor_ic(out[:64], nonce, (1 << 32) - 1, key)
    out3 += crypto_stream_xchacha20_xor_ic(out[64:128], nonce, (1 << 32), key)
    out3 += crypto_stream_xchacha20_xor_ic(
        out[128:], nonce, (1 << 32) + 1, key)
    assert out3 == out2

    assert final_out == out3

    assert not sodium_is_zero(crypto_stream_xchacha20_keygen())


@pytest.mark.skipif(has_crypto_stream_xchacha20,
                    reason='Requires minimal build of libsodium')
def test_stream_xchacha20_unavailable():
    key = crypto_stream_xchacha20_KEYBYTES * b'\x00'
    nonce = crypto_stream_xchacha20_NONCEBYTES * b'\x00'

    with pytest.raises(UnavailableError):
        crypto_stream_xchacha20_keygen()
    with pytest.raises(UnavailableError):
        crypto_stream_xchacha20(0, nonce, key)
    with pytest.raises(UnavailableError):
        crypto_stream_xchacha20_xor(b'a', nonce, key)
    with pytest.raises(UnavailableError):
        crypto_stream_xchacha20_xor_ic(b'a', nonce, 0, key)
