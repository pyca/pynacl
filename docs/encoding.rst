Encoders
========

.. currentmodule:: nacl.encoding

PyNaCl supports a simple method of encoding and decoding messages in different
formats. Encoders are simple classes with staticmethods that encode/decode and
are typically passed as a keyword argument `encoder` to various methods.

For example you can generate a signing key and encode it in hex with:

.. code-block:: python

    hex_key = nacl.signing.SigningKey.generate().encode(encoder=nacl.encoding.HexEncoder)

Then you can later decode it from hex:

.. code-block:: python

    signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)


Built in Encoders
-----------------

.. class:: RawEncoder

.. class:: HexEncoder

.. class:: Base16Encoder

.. class:: Base32Encoder

.. class:: Base64Encoder

.. class:: URLSafeBase64Encoder


Defining your own Encoder
-------------------------

Defining your own encoder is easy. Each encoder is simply a class with 2 static
methods. For example here is the hex encoder:

.. code-block:: python

    import binascii

    class HexEncoder(object):

        @staticmethod
        def encode(data):
            return binascii.hexlify(data)

        @staticmethod
        def decode(data):
            return binascii.unhexlify(data)
