Encoders
========

PyNaCl supports a simple method of encoding and decoding messages in different
formats. Encoders are simple classes with staticmethods that encode/decode and
are typically passed as a keyword argument `encoder` to various methods.

For example you can generate a signing key and encode it in hex with:

.. code:: python

    hex_key = nacl.signing.SigningKey.generate().encode(encoder=nacl.encoding.HexEncoder)

Then you can later decode it from hex:

.. code:: python

    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)


Built in Encoders
-----------------

.. autoclass:: nacl.encoding.RawEncoder
    :members:

.. autoclass:: nacl.encoding.HexEncoder
    :members:

.. autoclass:: nacl.encoding.Base16Encoder
    :members:

.. autoclass:: nacl.encoding.Base32Encoder
    :members:

.. autoclass:: nacl.encoding.Base64Encoder
    :members:


Defining your own Encoder
-------------------------

Defining your own encoder is easy. Each encoder is simply a class with 2 static
methods. For example here is the hex encoder:

.. code:: python

    import binascii

    class HexEncoder(object):

        @staticmethod
        def encode(data):
            return binascii.hexlify(data)

        @staticmethod
        def decode(data):
            return binascii.unhexlify(data)
