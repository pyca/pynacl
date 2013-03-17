#!/usr/bin/env python
import sys

from setuptools import setup
from setuptools.command.test import test as TestCommand

import nacl

try:
    import nacl.nacl
except ImportError:
    # installing - there is no cffi yet
    ext_modules = []
else:
    # building bdist - cffi is here!
    ext_modules = [nacl.nacl.ffi.verifier.get_extension()]


class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)


setup(
    name=nacl.__title__,
    version=nacl.__version__,

    description=nacl.__summary__,
    long_description=open("README.rst").read(),
    url=nacl.__uri__,
    license=nacl.__license__,

    author=nacl.__author__,
    author_email=nacl.__email__,

    install_requires=[
        "cffi",
    ],
    extras_require={
        "tests": ["pytest"],
    },
    tests_require=["pytest"],

    packages=[
        "nacl",
        "nacl.invoke",
    ],

    ext_package="nacl",
    ext_modules=ext_modules,

    zip_safe=False,
    cmdclass={"test": PyTest},
)
