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

from __future__ import absolute_import, division, print_function

import errno
import functools
import glob
import os
import os.path
import platform
import subprocess
import sys
from distutils.sysconfig import get_config_vars

from setuptools import Distribution, setup
from setuptools.command.build_ext import build_ext as _build_ext

try:
    from setuptools.command.build_clib import build_clib as _build_clib
except ImportError:
    from distutils.command.build_clib import build_clib as _build_clib


requirements = ["six"]
setup_requirements = ["setuptools"]
test_requirements = ["pytest>=3.2.1,!=3.3.0",
                     "hypothesis>=3.27.0"]
docs_requirements = ["sphinx>=1.6.5",
                     "sphinx_rtd_theme"]


if platform.python_implementation() == "PyPy":
    if sys.pypy_version_info < (2, 6):
        raise RuntimeError(
            "PyNaCl is not compatible with PyPy < 2.6. Please "
            "upgrade PyPy to use this library."
        )
else:
    requirements.append("cffi>=1.4.1")
    setup_requirements.append("cffi>=1.4.1")


def here(*paths):
    return os.path.relpath(os.path.join(*paths))


def abshere(*paths):
    return os.path.abspath(here(*paths))


sodium = functools.partial(here, "src/libsodium/src/libsodium")


sys.path.insert(0, abshere("src"))


import nacl  # noqa


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


def use_system():
    install_type = os.environ.get("SODIUM_INSTALL")

    if install_type == "system":
        # If we are forcing system installs, don't compile the bundled one
        return True
    else:
        # By default we just use the bundled copy
        return False


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

        # use Python's build environment variables
        build_env = {key: val for key, val in
                     get_config_vars().items() if key in
                     ("LDFLAGS", "CFLAGS", "CC", "CCSHARED", "LDSHARED") and
                     key not in os.environ}
        os.environ.update(build_env)

        # Ensure our temporary build directory exists
        build_temp = os.path.abspath(self.build_temp)
        try:
            os.makedirs(build_temp)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        # Ensure all of our executable files have their permission set
        for filename in [
                "src/libsodium/autogen.sh",
                "src/libsodium/compile",
                "src/libsodium/configure",
                "src/libsodium/depcomp",
                "src/libsodium/install-sh",
                "src/libsodium/missing",
                "src/libsodium/msvc-scripts/process.bat",
                "src/libsodium/test/default/wintest.bat"]:
            os.chmod(here(filename), 0o755)

        if not which("make"):
            raise Exception("ERROR: The 'make' utility is missing from PATH")

        # Locate our configure script
        configure = abshere("src/libsodium/configure")

        # Run ./configure
        configure_flags = ["--disable-shared", "--enable-static",
                           "--disable-debug", "--disable-dependency-tracking",
                           "--with-pic"]
        if platform.system() == "SunOS":
            # On Solaris, libssp doesn't link statically and causes linker
            # errors during import
            configure_flags.append("--disable-ssp")
        if os.environ.get('SODIUM_INSTALL_MINIMAL'):
            configure_flags.append("--enable-minimal")
        subprocess.check_call(
            [configure] + configure_flags +
            ["--prefix", os.path.abspath(self.build_clib)],
            cwd=build_temp,
        )

        make_args = os.environ.get('LIBSODIUM_MAKE_ARGS', '').split()
        # Build the library
        subprocess.check_call(["make"] + make_args, cwd=build_temp)

        # Check the build library
        subprocess.check_call(["make", "check"] + make_args, cwd=build_temp)

        # Install the built library
        subprocess.check_call(["make", "install"] + make_args, cwd=build_temp)


class build_ext(_build_ext):

    def run(self):
        if self.distribution.has_c_libraries():
            build_clib = self.get_finalized_command("build_clib")
            self.include_dirs.append(
                os.path.join(build_clib.build_clib, "include"),
            )
            self.library_dirs.insert(
                0, os.path.join(build_clib.build_clib, "lib64"),
            )
            self.library_dirs.insert(
                0, os.path.join(build_clib.build_clib, "lib"),
            )

        return _build_ext.run(self)


README = open("README.rst").read()
INSTALL = open("INSTALL.rst").read()
CHANGELOG = open("CHANGELOG.rst").read()


setup(
    name=nacl.__title__,
    version=nacl.__version__,

    description=nacl.__summary__,
    long_description='\n'.join((README, INSTALL, CHANGELOG)),
    url=nacl.__uri__,
    license=nacl.__license__,

    author=nacl.__author__,
    author_email=nacl.__email__,
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*",
    setup_requires=setup_requirements,
    install_requires=requirements,
    extras_require={
        "tests": test_requirements,
        "docs": docs_requirements,
    },
    tests_require=test_requirements,

    package_dir={"": "src"},
    packages=[
        "nacl",
        "nacl.pwhash",
        "nacl.bindings",
    ],

    ext_package="nacl",
    cffi_modules=[
        "src/bindings/build.py:ffi",
    ],

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
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ]
)
