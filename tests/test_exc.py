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


import pytest

from nacl import exceptions as exc


class CustomError(exc.CryptoError):
    pass


def test_exceptions_ensure_with_true_condition():
    exc.ensure(True, "one equals one")


def test_exceptions_ensure_with_false_condition():
    with pytest.raises(exc.AssertionError):
        exc.ensure(
            False,
            "one is not zero",
            raising=exc.AssertionError,
        )


def test_exceptions_ensure_with_unwanted_kwarg():
    with pytest.raises(exc.TypeError):
        exc.ensure(
            True,
            unexpected="unexpected",  # type: ignore[arg-type]
        )


def test_exceptions_ensure_custom_exception():
    with pytest.raises(CustomError):
        exc.ensure(
            False,
            "Raising a CustomError",
            raising=CustomError,
        )
