from . import nacl


def random(size=32):
    data = nacl.ffi.new("unsigned char[]", size)
    nacl.lib.randombytes(data, size)
    return nacl.ffi.buffer(data, size)[:]
