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

import glob
import os.path

import six

# We need to import this prior to importing cffi to fix prebuilding the
#   extension modules
from nacl import _cffi_fix

from cffi import FFI
from cffi.verifier import Verifier


__all__ = ["ffi"]


HEADERS = glob.glob(
    os.path.join(os.path.abspath(os.path.dirname(__file__)), "*.h")
)


# Build our FFI instance
ffi = FFI()


# Add all of our header files
for header in HEADERS:
    with open(header, "r") as hfile:
        ffi.cdef(hfile.read())


# TODO: Can we use the ABI of libsodium for this instead?
ffi.verifier = Verifier(ffi,
    "#include <sodium.h>",

    # We need to link to the sodium library
    libraries=["sodium"],

    # Our ext_package is nacl so look for it
    ext_package="nacl._lib",
)


class Library(object):

    def __init__(self, ffi):
        self.ffi = ffi
        self._initalized = False

        # This prevents the compile_module() from being called, the module
        # should have been compiled by setup.py
        def _compile_module(*args, **kwargs):
            raise RuntimeError("Cannot compile module during runtime")
        self.ffi.verifier.compile_module = _compile_module

    def __getattr__(self, name):
        if not self._initalized:
            self._lib = self.ffi.verifier.load_library()

        # redirect attribute access to the underlying lib
        attr = getattr(self._lib, name)

        # Go ahead and assign the returned value to this class so we don't
        # need to do this lookup again
        setattr(self, name, attr)

        return attr

lib = Library(ffi)
