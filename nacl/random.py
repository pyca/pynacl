from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

from . import nacl


def random(size=32):
    data = nacl.ffi.new("unsigned char[]", size)
    nacl.lib.randombytes(data, size)
    return nacl.ffi.buffer(data, size)[:]
