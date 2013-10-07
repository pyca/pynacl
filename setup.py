#!/usr/bin/env python
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
import functools
import glob
import os
import os.path
import subprocess
import sys

from distutils.command.build_clib import build_clib as _build_clib
from distutils.command.build_ext import build_ext as _build_ext

from setuptools import Distribution, setup


SODIUM_MAJOR = 4
SODIUM_MINOR = 3


def here(*paths):
    return os.path.abspath(os.path.join(os.path.dirname(__file__), *paths))

sodium = functools.partial(here, "src/libsodium/src/libsodium")


sys.path.append(here("src"))


import nacl


def which(name, flags=os.X_OK):  # Taken from twisted
    result = []
    exts = filter(None, os.environ.get('PATHEXT', '').split(os.pathsep))
    path = os.environ.get('PATH', None)
    if path is None:
        return []
    for p in os.environ.get('PATH', '').split(os.pathsep):
        p = os.path.join(p, name)
        if os.access(p, flags):
            result.append(p)
        for e in exts:
            pext = p + e
            if os.access(pext, flags):
                result.append(pext)
    return result


# This hack exists so that we can import nacl here
sys.path += glob.glob("*.egg")

try:
    import nacl._lib
except ImportError:
    # installing - there is no cffi yet
    ext_modules = []
else:
    # building bdist - cffi is here!
    ext_modules = [nacl._lib.ffi.verifier.get_extension()]


def use_system():
    install_type = os.environ.get("SODIUM_INSTALL")

    if install_type == "system":
        # If we are forcing system installs, don't compile the bundled one
        return True
    elif install_type == "bundled":
        # If we are forcing bundled installs, compile it
        return False

    # Detect if we have libsodium available
    import cffi

    ffi = cffi.FFI()
    ffi.cdef("""
        int sodium_library_version_major();
        int sodium_library_version_minor();
    """)

    try:
        system = ffi.dlopen("libsodium")
    except OSError:
        # We couldn't locate libsodium so we'll use the bundled one
        return False

    if system.sodium_library_version_major() != SODIUM_MAJOR:
        return False

    if system.sodium_library_version_minor() < SODIUM_MINOR:
        return False

    # If we got this far then the system library should be good enough
    return True


class Distribution(Distribution):

    def has_c_libraries(self):
        return not use_system()


class build_clib(_build_clib):

    def get_source_files(self):
        files = glob.glob(here("src/libsodium/*"))
        files += glob.glob(here("src/libsodium/*/*"))
        files += glob.glob(here("src/libsodium/*/*/*"))
        files += glob.glob(here("src/libsodium/*/*/*/*"))
        files += glob.glob(here("src/libsodium/*/*/*/*/*"))
        files += glob.glob(here("src/libsodium/*/*/*/*/*/*"))

        return files

    def build_libraries(self, libraries):
        raise Exception("build_libraries")

    def check_library_list(self, libraries):
        raise Exception("check_library_list")

    def get_library_names(self):
        return ["sodium"]

    def run(self):
        if use_system():
            return

        build_temp = os.path.abspath(self.build_temp)

        # Ensure our temporary build directory exists
        try:
            os.makedirs(build_temp)
        except IOError:
            pass

        # Locate our configure script
        configure = here("src/libsodium/configure")

        # Run ./configure
        subprocess.check_call(
            [
                configure, "--disable-shared", "--enable-static",
                "--disable-debug", "--disable-dependency-tracking",
                "--with-pic", "--prefix", os.path.abspath(self.build_clib),
            ],
            cwd=build_temp,
        )

        # Build the library
        subprocess.check_call(["make"], cwd=build_temp)

        # Check the build library
        subprocess.check_call(["make", "check"], cwd=build_temp)

        # Install the built library
        subprocess.check_call(["make", "install"], cwd=build_temp)


class build_ext(_build_ext):

    def run(self):
        if self.distribution.has_c_libraries():
            build_clib = self.get_finalized_command("build_clib")
            self.include_dirs.append(
                os.path.join(build_clib.build_clib, "include"),
            )
            self.library_dirs.append(
                os.path.join(build_clib.build_clib, "lib"),
            )

        return _build_ext.run(self)


setup(
    name=nacl.__title__,
    version=nacl.__version__,

    description=nacl.__summary__,
    long_description=open("README.rst").read(),
    url=nacl.__uri__,
    license=nacl.__license__,

    author=nacl.__author__,
    author_email=nacl.__email__,

    setup_requires=[
        "cffi",
    ],
    install_requires=[
        "cffi",
        "six",
    ],
    extras_require={
        "tests": ["pytest"],
    },
    tests_require=["pytest"],

    package_dir={"": "src"},
    packages=[
        "nacl",
        "nacl._lib",
        "nacl.c",
    ],
    package_data={"nacl._lib": ["*.h"]},

    ext_package="nacl._lib",
    ext_modules=ext_modules,

    cmdclass={
        "build_clib": build_clib,
        "build_ext": build_ext,
    },
    distclass=Distribution,
    zip_safe=False,

    classifiers=[
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
    ]
)
