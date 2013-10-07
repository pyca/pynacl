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


# Compile our module
# TODO: Can we use the ABI of libsodium for this instead?
lib = ffi.verify(
    "#include <sodium.h>",

    # We need to link to the sodium library
    libraries=["sodium"],

    # Our ext_package is nacl so look for it
    ext_package="nacl._lib",
)


# Put all of the exposed functions onto the module
g = globals()
for name, function in six.iteritems(lib.__dict__):
    # Add this function to the __all__ namespace
    __all__.append(name)

    # Add this function to the globals
    g[name] = function
