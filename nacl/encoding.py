import base64
import binascii

from . import six


class Encoder(object):

    def __init__(self):
        self._registry = {}

    def __getitem__(self, name):
        if isinstance(name, six.string_types):
            return self._registry[name]
        return name

    def register(self, name, cls=None):
        if cls is None:
            def inner(cls):
                self._registry[name] = cls()
                return cls
            return inner
        else:
            self._registry[name] = cls()


# Global encoder
encoder = Encoder()


@encoder.register("raw")
class RawEncoder(object):

    def encode(self, data):
        return data

    def decode(self, data):
        return data


@encoder.register("hex")
class HexEncoder(object):

    def encode(self, data):
        return binascii.hexlify(data)

    def decode(self, data):
        return binascii.unhexlify(data)


@encoder.register("base16")
class Base16Encoder(object):

    def encode(self, data):
        return base64.b16encode(data)

    def decode(self, data):
        return base64.b16decode(data)


@encoder.register("base32")
class Base32Encoder(object):

    def encode(self, data):
        return base64.b32encode(data)

    def decode(self, data):
        return base64.b32decode(data)


@encoder.register("base64")
class Base64Encoder(object):

    def encode(self, data):
        return base64.b64encode(data)

    def decode(self, data):
        return base64.b64decode(data)
