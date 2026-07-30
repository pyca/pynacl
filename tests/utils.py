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


from __future__ import annotations

import os
from typing import Callable

import pytest


def assert_equal(x: object, y: object) -> None:
    assert x == y
    # Deliberately exercises `!=` to check `__ne__` consistency
    assert not (x != y)  # noqa: SIM202


def assert_not_equal(x: object, y: object) -> None:
    assert x != y
    # Deliberately exercises `==` to check `__eq__` consistency
    assert not (x == y)  # noqa: SIM201


def read_crypto_test_vectors(
    fname: str, maxels: int = 0, delimiter: bytes | None = None
) -> list[tuple[bytes, ...]]:
    assert delimiter is not None and isinstance(delimiter, bytes)
    vectors = []
    path = os.path.join(os.path.dirname(__file__), "data", fname)
    with open(path, "rb") as fp:
        for line in fp:
            line = line.rstrip()
            if line and line[0] != b"#"[0]:
                splt = [x for x in line.split(delimiter)]
                if maxels:
                    splt = splt[:maxels]
                vectors.append(tuple(splt))
    return vectors


def read_kv_test_vectors(
    fname: str,
    delimiter: bytes | None = None,
    newrecord: bytes | None = None,
) -> list[dict[str, bytes]]:
    assert delimiter is not None and isinstance(delimiter, bytes)
    assert newrecord is not None and isinstance(newrecord, bytes)
    vectors = []
    path = os.path.join(os.path.dirname(__file__), "data", fname)
    vector: dict[str, bytes] = {}
    with open(path, "rb") as fp:
        for line in fp:
            line = line.rstrip()
            if line and line[0] != b"#"[0]:
                [k, v] = line.split(delimiter, 1)
                k, v = k.strip(), v.strip()
                if k == newrecord and k.decode("utf-8") in vector:
                    vectors.append(vector)
                    vector = {}
                vector[k.decode("utf-8")] = v
        vectors.append(vector)
    return vectors


def flip_byte(original: bytes, byte_offset: int) -> bytes:
    return (
        original[:byte_offset]
        + bytes([0x01 ^ original[byte_offset]])
        + original[byte_offset + 1 :]
    )


# Type safety: it's fine to use `...` here, but mypy config doesn't like it because it's
# an explicit `Any`.
def check_type_error(  # type: ignore[explicit-any]
    expected: str, f: Callable[..., object], *args: object
) -> None:
    with pytest.raises(TypeError) as e:
        f(*args)
    assert expected in str(e.value)
