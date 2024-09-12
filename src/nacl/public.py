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
from abc import ABCMeta, abstractmethod
from typing import ClassVar, Generic, Optional, Tuple, Type, TypeVar

import nacl.bindings
from nacl import encoding
from nacl import exceptions as exc
from nacl.encoding import Encoder
from nacl.utils import EncryptedMessage, StringFixer, random


class PublicKey(encoding.Encodable, StringFixer):
    """
    The public key counterpart to an Curve25519 :class:`nacl.public.PrivateKey`
    for encrypting messages.

    :param public_key: [:class:`bytes`] Encoded Curve25519 public key
    :param encoder: A class that is able to decode the `public_key`

    :cvar SIZE: The size that the public key is required to be
    """

    SIZE: ClassVar[int] = nacl.bindings.crypto_box_PUBLICKEYBYTES

    def __init__(
        self,
        public_key: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ):
        self._public_key = encoder.decode(public_key)
        if not isinstance(self._public_key, bytes):
            raise exc.TypeError(
                "PublicKey must be created from {} bytes".format(self.SIZE)
            )

        if len(self._public_key) != self.SIZE:
            raise exc.ValueError(
                "The public key must be exactly {} bytes long".format(
                    self.SIZE
                )
            )

    def __bytes__(self) -> bytes:
        return self._public_key

    def __hash__(self) -> int:
        return hash(bytes(self))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False
        return nacl.bindings.sodium_memcmp(bytes(self), bytes(other))

    def __ne__(self, other: object) -> bool:
        return not (self == other)


class PrivateKey(encoding.Encodable, StringFixer):
    """
    Private key for decrypting messages using the Curve25519 algorithm.

    .. warning:: This **must** be protected and remain secret. Anyone who
        knows the value of your :class:`~nacl.public.PrivateKey` can decrypt
        any message encrypted by the corresponding
        :class:`~nacl.public.PublicKey`

    :param private_key: The private key used to decrypt messages
    :param encoder: The encoder class used to decode the given keys

    :cvar SIZE: The size that the private key is required to be
    :cvar SEED_SIZE: The size that the seed used to generate the
                     private key is required to be
    """

    SIZE: ClassVar[int] = nacl.bindings.crypto_box_SECRETKEYBYTES
    SEED_SIZE: ClassVar[int] = nacl.bindings.crypto_box_SEEDBYTES

    def __init__(
        self,
        private_key: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ):
        # Decode the secret_key
        private_key = encoder.decode(private_key)
        # verify the given secret key type and size are correct
        if not (
            isinstance(private_key, bytes) and len(private_key) == self.SIZE
        ):
            raise exc.TypeError(
                (
                    "PrivateKey must be created from a {} "
                    "bytes long raw secret key"
                ).format(self.SIZE)
            )

        raw_public_key = nacl.bindings.crypto_scalarmult_base(private_key)

        self._private_key = private_key
        self.public_key = PublicKey(raw_public_key)

    @classmethod
    def from_seed(
        cls,
        seed: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> "PrivateKey":
        """
        Generate a PrivateKey using a deterministic construction
        starting from a caller-provided seed

        .. warning:: The seed **must** be high-entropy; therefore,
            its generator **must** be a cryptographic quality
            random function like, for example, :func:`~nacl.utils.random`.

        .. warning:: The seed **must** be protected and remain secret.
            Anyone who knows the seed is really in possession of
            the corresponding PrivateKey.

        :param seed: The seed used to generate the private key
        :rtype: :class:`~nacl.public.PrivateKey`
        """
        # decode the seed
        seed = encoder.decode(seed)
        # Verify the given seed type and size are correct
        if not (isinstance(seed, bytes) and len(seed) == cls.SEED_SIZE):
            raise exc.TypeError(
                (
                    "PrivateKey seed must be a {} bytes long "
                    "binary sequence"
                ).format(cls.SEED_SIZE)
            )
        # generate a raw key pair from the given seed
        raw_pk, raw_sk = nacl.bindings.crypto_box_seed_keypair(seed)
        # construct a instance from the raw secret key
        return cls(raw_sk)

    def __bytes__(self) -> bytes:
        return self._private_key

    def __hash__(self) -> int:
        return hash((type(self), bytes(self.public_key)))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False
        return self.public_key == other.public_key

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    @classmethod
    def generate(cls) -> "PrivateKey":
        """
        Generates a random :class:`~nacl.public.PrivateKey` object

        :rtype: :class:`~nacl.public.PrivateKey`
        """
        return cls(random(PrivateKey.SIZE), encoder=encoding.RawEncoder)


_Box = TypeVar("_Box", bound="Box")


class Box(encoding.Encodable, StringFixer):
    """
    The Box class boxes and unboxes messages between a pair of keys

    The ciphertexts generated by :class:`~nacl.public.Box` include a 16
    byte authenticator which is checked as part of the decryption. An invalid
    authenticator will cause the decrypt function to raise an exception. The
    authenticator is not a signature. Once you've decrypted the message you've
    demonstrated the ability to create arbitrary valid message, so messages you
    send are repudiable. For non-repudiable messages, sign them after
    encryption.

    :param private_key: :class:`~nacl.public.PrivateKey` used to encrypt and
        decrypt messages
    :param public_key: :class:`~nacl.public.PublicKey` used to encrypt and
        decrypt messages

    :cvar NONCE_SIZE: The size that the nonce is required to be.
    """

    NONCE_SIZE: ClassVar[int] = nacl.bindings.crypto_box_NONCEBYTES
    _shared_key: bytes

    def __init__(self, private_key: PrivateKey, public_key: PublicKey):
        if not isinstance(private_key, PrivateKey) or not isinstance(
            public_key, PublicKey
        ):
            raise exc.TypeError(
                "Box must be created from a PrivateKey and a PublicKey"
            )
        self._shared_key = nacl.bindings.crypto_box_beforenm(
            public_key.encode(encoder=encoding.RawEncoder),
            private_key.encode(encoder=encoding.RawEncoder),
        )

    def __bytes__(self) -> bytes:
        return self._shared_key

    @classmethod
    def decode(
        cls: Type[_Box], encoded: bytes, encoder: Encoder = encoding.RawEncoder
    ) -> _Box:
        """
        Alternative constructor. Creates a Box from an existing Box's shared key.
        """
        # Create an empty box
        box: _Box = cls.__new__(cls)

        # Assign our decoded value to the shared key of the box
        box._shared_key = encoder.decode(encoded)

        return box

    def encrypt(
        self,
        plaintext: bytes,
        nonce: Optional[bytes] = None,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> EncryptedMessage:
        """
        Encrypts the plaintext message using the given `nonce` (or generates
        one randomly if omitted) and returns the ciphertext encoded with the
        encoder.

        .. warning:: It is **VITALLY** important that the nonce is a nonce,
            i.e. it is a number used only once for any given key. If you fail
            to do this, you compromise the privacy of the messages encrypted.

        :param plaintext: [:class:`bytes`] The plaintext message to encrypt
        :param nonce: [:class:`bytes`] The nonce to use in the encryption
        :param encoder: The encoder to use to encode the ciphertext
        :rtype: [:class:`nacl.utils.EncryptedMessage`]
        """
        if nonce is None:
            nonce = random(self.NONCE_SIZE)

        if len(nonce) != self.NONCE_SIZE:
            raise exc.ValueError(
                "The nonce must be exactly %s bytes long" % self.NONCE_SIZE
            )

        ciphertext = nacl.bindings.crypto_box_easy_afternm(
            plaintext,
            nonce,
            self._shared_key,
        )

        encoded_nonce = encoder.encode(nonce)
        encoded_ciphertext = encoder.encode(ciphertext)

        return EncryptedMessage._from_parts(
            encoded_nonce,
            encoded_ciphertext,
            encoder.encode(nonce + ciphertext),
        )

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: Optional[bytes] = None,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> bytes:
        """
        Decrypts the ciphertext using the `nonce` (explicitly, when passed as a
        parameter or implicitly, when omitted, as part of the ciphertext) and
        returns the plaintext message.

        :param ciphertext: [:class:`bytes`] The encrypted message to decrypt
        :param nonce: [:class:`bytes`] The nonce used when encrypting the
            ciphertext
        :param encoder: The encoder used to decode the ciphertext.
        :rtype: [:class:`bytes`]
        """
        # Decode our ciphertext
        ciphertext = encoder.decode(ciphertext)

        if nonce is None:
            # If we were given the nonce and ciphertext combined, split them.
            nonce = ciphertext[: self.NONCE_SIZE]
            ciphertext = ciphertext[self.NONCE_SIZE :]

        if len(nonce) != self.NONCE_SIZE:
            raise exc.ValueError(
                "The nonce must be exactly %s bytes long" % self.NONCE_SIZE
            )

        plaintext = nacl.bindings.crypto_box_open_easy_afternm(
            ciphertext,
            nonce,
            self._shared_key,
        )

        return plaintext

    def shared_key(self) -> bytes:
        """
        Returns the Curve25519 shared secret, that can then be used as a key in
        other symmetric ciphers.

        .. warning:: It is **VITALLY** important that you use a nonce with your
            symmetric cipher. If you fail to do this, you compromise the
            privacy of the messages encrypted. Ensure that the key length of
            your cipher is 32 bytes.
        :rtype: [:class:`bytes`]
        """

        return self._shared_key


_Key = TypeVar("_Key", PublicKey, PrivateKey)


class SealedBox(Generic[_Key], encoding.Encodable, StringFixer):
    """
    The SealedBox class boxes and unboxes messages addressed to
    a specified key-pair by using ephemeral sender's key pairs,
    whose private part will be discarded just after encrypting
    a single plaintext message.

    The ciphertexts generated by :class:`~nacl.public.SecretBox` include
    the public part of the ephemeral key before the :class:`~nacl.public.Box`
    ciphertext.

    :param recipient_key: a :class:`~nacl.public.PublicKey` used to encrypt
        messages and derive nonces, or a :class:`~nacl.public.PrivateKey` used
        to decrypt messages.

    .. versionadded:: 1.2
    """

    _public_key: bytes
    _private_key: Optional[bytes]

    def __init__(self, recipient_key: _Key):
        if isinstance(recipient_key, PublicKey):
            self._public_key = recipient_key.encode(
                encoder=encoding.RawEncoder
            )
            self._private_key = None
        elif isinstance(recipient_key, PrivateKey):
            self._private_key = recipient_key.encode(
                encoder=encoding.RawEncoder
            )
            self._public_key = recipient_key.public_key.encode(
                encoder=encoding.RawEncoder
            )
        else:
            raise exc.TypeError(
                "SealedBox must be created from a PublicKey or a PrivateKey"
            )

    def __bytes__(self) -> bytes:
        return self._public_key

    def encrypt(
        self,
        plaintext: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> bytes:
        """
        Encrypts the plaintext message using a random-generated ephemeral
        key pair and returns a "composed ciphertext", containing both
        the public part of the key pair and the ciphertext proper,
        encoded with the encoder.

        The private part of the ephemeral key-pair will be scrubbed before
        returning the ciphertext, therefore, the sender will not be able to
        decrypt the generated ciphertext.

        :param plaintext: [:class:`bytes`] The plaintext message to encrypt
        :param encoder: The encoder to use to encode the ciphertext
        :return bytes: encoded ciphertext
        """

        ciphertext = nacl.bindings.crypto_box_seal(plaintext, self._public_key)

        encoded_ciphertext = encoder.encode(ciphertext)

        return encoded_ciphertext

    def decrypt(
        self: "SealedBox[PrivateKey]",
        ciphertext: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> bytes:
        """
        Decrypts the ciphertext using the ephemeral public key enclosed
        in the ciphertext and the SealedBox private key, returning
        the plaintext message.

        :param ciphertext: [:class:`bytes`] The encrypted message to decrypt
        :param encoder: The encoder used to decode the ciphertext.
        :return bytes: The original plaintext
        :raises TypeError: if this SealedBox was created with a
            :class:`~nacl.public.PublicKey` rather than a
            :class:`~nacl.public.PrivateKey`.
        """
        # Decode our ciphertext
        ciphertext = encoder.decode(ciphertext)

        if self._private_key is None:
            raise TypeError(
                "SealedBoxes created with a public key cannot decrypt"
            )
        plaintext = nacl.bindings.crypto_box_seal_open(
            ciphertext,
            self._public_key,
            self._private_key,
        )

        return plaintext


class PublicKx(encoding.Encodable, StringFixer):
    """
    The public key counterpart to an Curve25519 :class:`nacl.public.PrivateKx`
    for encrypting messages.

    :param public_key: [:class:`bytes`] Encoded Curve25519 public key
    :param encoder: A class that is able to decode the `public_key`

    :cvar SIZE: The size that the public key is required to be
    """

    SIZE: ClassVar[int] = nacl.bindings.crypto_kx_PUBLIC_KEY_BYTES

    def __init__(
        self,
        public_key: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ):
        self._public_key = encoder.decode(public_key)
        if not isinstance(self._public_key, bytes):
            raise exc.TypeError(
                "PublicKx must be created from {} bytes".format(self.SIZE)
            )

        if len(self._public_key) != self.SIZE:
            raise exc.ValueError(
                "The public key must be exactly {} bytes long".format(
                    self.SIZE
                )
            )

    def __bytes__(self) -> bytes:
        return self._public_key

    def __hash__(self) -> int:
        return hash(bytes(self))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False
        return nacl.bindings.sodium_memcmp(bytes(self), bytes(other))

    def __ne__(self, other: object) -> bool:
        return not (self == other)


class PrivateKx(encoding.Encodable, StringFixer):
    """
    Private key for decrypting messages using the Curve25519 algorithm.

    .. warning:: This **must** be protected and remain secret. Anyone who
        knows the value of your :class:`~nacl.public.PrivateKx` can decrypt
        any message encrypted by the corresponding
        :class:`~nacl.public.PublicKx`

    :param private_key: The private key used to decrypt messages
    :param encoder: The encoder class used to decode the given keys

    :cvar SIZE: The size that the private key is required to be
    :cvar SEED_SIZE: The size that the seed used to generate the
                     private key is required to be
    """

    SIZE: ClassVar[int] = nacl.bindings.crypto_kx_SECRET_KEY_BYTES
    SEED_SIZE: ClassVar[int] = nacl.bindings.crypto_kx_SEED_BYTES

    def __init__(
        self,
        private_key: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ):
        # Decode the secret_key
        private_key = encoder.decode(private_key)
        # verify the given secret key type and size are correct
        if not (
            isinstance(private_key, bytes) and len(private_key) == self.SIZE
        ):
            raise exc.TypeError(
                (
                    "PrivateKx must be created from a {} "
                    "bytes long raw secret key"
                ).format(self.SIZE)
            )

        raw_public_key = nacl.bindings.crypto_scalarmult_base(private_key)

        self._private_key = private_key
        self.public_key = PublicKx(raw_public_key)

    @classmethod
    def from_seed(
        cls,
        seed: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> "PrivateKx":
        """
        Generate a PrivateKx using a deterministic construction
        starting from a caller-provided seed

        .. warning:: The seed **must** be high-entropy; therefore,
            its generator **must** be a cryptographic quality
            random function like, for example, :func:`~nacl.utils.random`.

        .. warning:: The seed **must** be protected and remain secret.
            Anyone who knows the seed is really in possession of
            the corresponding PrivateKx.

        :param seed: The seed used to generate the private key
        :rtype: :class:`~nacl.public.PrivateKx`
        """
        # decode the seed
        seed = encoder.decode(seed)
        # Verify the given seed type and size are correct
        if not (isinstance(seed, bytes) and len(seed) == cls.SEED_SIZE):
            raise exc.TypeError(
                (
                    "PrivateKx seed must be a {} bytes long " "binary sequence"
                ).format(cls.SEED_SIZE)
            )
        # generate a raw key pair from the given seed
        raw_pk, raw_sk = nacl.bindings.crypto_kx_seed_keypair(seed)
        # construct a instance from the raw secret key
        return cls(raw_sk)

    def __bytes__(self) -> bytes:
        return self._private_key

    def __hash__(self) -> int:
        return hash((type(self), bytes(self.public_key)))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False
        return self.public_key == other.public_key

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    @classmethod
    def generate(cls) -> "PrivateKx":
        """
        Generates a random :class:`~nacl.public.PrivateKx` object

        :rtype: :class:`~nacl.public.PrivateKx`
        """
        return cls(random(PrivateKx.SIZE), encoder=encoding.RawEncoder)


AeadKx = TypeVar("AeadKx", bound="_AeadKx")


class _AeadKx(metaclass=ABCMeta):
    """
    The _AeadKx class serves as the base class for
    :class:`~nacl.public.AeadClient` and
    :class:`~nacl.public.AeadServer.

    :param private_key: :class:`~nacl.public.PrivateKx` used to encrypt and
        decrypt messages
    :param public_key: :class:`~nacl.public.PublicKx` used to encrypt and
        decrypt messages

    :cvar NONCE_SIZE: The size that the nonce is required to be.
    """

    NONCE_SIZE: ClassVar[int] = (
        nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    )
    _rx_key: bytes
    _tx_key: bytes

    def __init__(self, private_key: PrivateKx, public_key: PublicKx):
        if not isinstance(private_key, PrivateKx) or not isinstance(
            public_key, PublicKx
        ):
            raise exc.TypeError(
                "{} must be created from a PrivateKx and a PublicKx".format(
                    self.__class__.__name__
                )
            )
        self._rx_key, self._tx_key = self._kx_session_keys(
            private_key, public_key
        )

    @abstractmethod
    def _kx_session_keys(
        self, private_key: PrivateKx, public_key: PublicKx
    ) -> Tuple[bytes, bytes]:
        """Computes rx and tx keys"""

    @classmethod
    @abstractmethod
    def decode(
        cls: Type[AeadKx],
        encoded: bytes,
        encoder: Encoder = encoding.RawEncoder,
    ) -> AeadKx:
        """Decodes from encoded bytes"""

    def __bytes__(self) -> bytes:
        return self._rx_key + self._tx_key

    @classmethod
    def _decode(
        cls: Type[AeadKx],
        encoded: bytes,
        encoder: Encoder = encoding.RawEncoder,
    ) -> AeadKx:
        """
        Alternative constructor. Creates from rx key + tx key.
        """
        # Create an empty class
        aeadKx = cls.__new__(cls)

        # Assign our decoded value to both keys
        rx_key = encoded[: nacl.bindings.crypto_kx_SESSION_KEY_BYTES]
        tx_key = encoded[nacl.bindings.crypto_kx_SESSION_KEY_BYTES :]
        aeadKx._rx_key = encoder.decode(rx_key)
        aeadKx._tx_key = encoder.decode(tx_key)

        return aeadKx

    def encrypt(
        self,
        plaintext: bytes,
        aad: bytes = b"",
        nonce: Optional[bytes] = None,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> EncryptedMessage:
        """
        Encrypts the plaintext message using the given `nonce` (or generates
        one randomly if omitted) and returns the ciphertext encoded with the
        encoder.

        .. warning:: It is vitally important for :param nonce: to be unique.
            By default, it is generated randomly; [:class:`_AeadKx`] uses XChacha20
            for extended (192b) nonce size, so the risk of reusing random nonces
            is negligible.  It is *strongly recommended* to keep this behaviour,
            as nonce reuse will compromise the privacy of encrypted messages.
            Should implicit nonces be inadequate for your application, the
            second best option is using split counters; e.g. if sending messages
            encrypted under a shared key between 2 users, each user can use the
            number of messages it sent so far, prefixed or suffixed with a 1bit
            user id.  Note that the counter must **never** be rolled back (due
            to overflow, on-disk state being rolled back to an earlier backup,
            ...)

        :param plaintext: [:class:`bytes`] The plaintext message to encrypt
        :param aad: [:class:`bytes`] additional authenticated data
        :param nonce: [:class:`bytes`] The nonce to use in the encryption
        :param encoder: The encoder to use to encode the ciphertext
        :rtype: [:class:`nacl.utils.EncryptedMessage`]
        """
        if nonce is None:
            nonce = random(self.NONCE_SIZE)

        if len(nonce) != self.NONCE_SIZE:
            raise exc.ValueError(
                "The nonce must be exactly %s bytes long" % self.NONCE_SIZE
            )

        ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, nonce, self._tx_key
        )

        encoded_nonce = encoder.encode(nonce)
        encoded_ciphertext = encoder.encode(ciphertext)

        return EncryptedMessage._from_parts(
            encoded_nonce,
            encoded_ciphertext,
            encoder.encode(nonce + ciphertext),
        )

    def _decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        aad: bytes = b"",
        nonce: Optional[bytes] = None,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> bytes:
        ciphertext = encoder.decode(ciphertext)

        if nonce is None:
            # If we were given the nonce and ciphertext combined, split them.
            nonce = ciphertext[: self.NONCE_SIZE]
            ciphertext = ciphertext[self.NONCE_SIZE :]

        if len(nonce) != self.NONCE_SIZE:
            raise exc.ValueError(
                "The nonce must be exactly %s bytes long" % self.NONCE_SIZE
            )

        plaintext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, aad, nonce, key
        )

        return plaintext

    def decrypt(
        self,
        ciphertext: bytes,
        aad: bytes = b"",
        nonce: Optional[bytes] = None,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> bytes:
        """
        Decrypts the ciphertext using the `nonce` (explicitly, when passed as a
        parameter or implicitly, when omitted, as part of the ciphertext) and
        returns the plaintext message.

        :param ciphertext: [:class:`bytes`] The encrypted message to decrypt
        :param aad: [:class:`bytes`] additional authenticated data
        :param nonce: [:class:`bytes`] The nonce used when encrypting the
            ciphertext
        :param encoder: The encoder used to decode the ciphertext.
        :rtype: [:class:`bytes`]
        """
        # Decode our ciphertext
        return self._decrypt(ciphertext, self._rx_key, aad, nonce, encoder)

    def decrypt_beforetx(
        self,
        ciphertext: bytes,
        aad: bytes = b"",
        nonce: Optional[bytes] = None,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> bytes:
        """
        Decrypts the ciphertext using the `nonce` (explicitly, when passed as a
        parameter or implicitly, when omitted, as part of the ciphertext) and
        returns the plaintext message.

        :param ciphertext: [:class:`bytes`] The encrypted message to decrypt
        :param aad: [:class:`bytes`] additional authenticated data
        :param nonce: [:class:`bytes`] The nonce used when encrypting the
            ciphertext
        :param encoder: The encoder used to decode the ciphertext.
        :rtype: [:class:`bytes`]
        """
        # Decode our ciphertext
        return self._decrypt(ciphertext, self._tx_key, aad, nonce, encoder)

    def rx_key(self) -> bytes:
        """
        Returns the Curve25519 rx secret

        .. warning:: It is **VITALLY** important that you use a nonce with your
            symmetric cipher. If you fail to do this, you compromise the
            privacy of the messages encrypted. Ensure that the key length of
            your cipher is 32 bytes.
        :rtype: [:class:`bytes`]
        """
        return self._rx_key

    def tx_key(self) -> bytes:
        """
        Returns the Curve25519 tx secret

        .. warning:: It is **VITALLY** important that you use a nonce with your
            symmetric cipher. If you fail to do this, you compromise the
            privacy of the messages encrypted. Ensure that the key length of
            your cipher is 32 bytes.
        :rtype: [:class:`bytes`]
        """
        return self._tx_key


_AeadClient = TypeVar("_AeadClient", bound="AeadClient")


class AeadClient(_AeadKx, encoding.Encodable, StringFixer):
    """
    The AeadClient class boxes and unboxes messages between a pair of keys

    The ciphertexts generated by :class:`~nacl.public.AeadClient` include a 16
    byte authenticator which is checked as part of the decryption. An invalid
    authenticator will cause the decrypt function to raise an exception. The
    authenticator is not a signature. Once you've decrypted the message you've
    demonstrated the ability to create arbitrary valid message, so messages you
    send are repudiable. For non-repudiable messages, sign them after
    encryption.

    :param private_key: :class:`~nacl.public.PrivateKx` used to encrypt and
        decrypt messages
    :param public_key: :class:`~nacl.public.PublicKx` used to encrypt and
        decrypt messages

    :cvar NONCE_SIZE: The size that the nonce is required to be.
    """

    def _kx_session_keys(
        self, private_key: PrivateKx, public_key: PublicKx
    ) -> Tuple[bytes, bytes]:
        return nacl.bindings.crypto_kx_client_session_keys(
            private_key.public_key.encode(encoder=encoding.RawEncoder),
            private_key.encode(encoder=encoding.RawEncoder),
            public_key.encode(encoder=encoding.RawEncoder),
        )

    @classmethod
    def decode(
        cls: Type[_AeadClient],
        encoded: bytes,
        encoder: Encoder = encoding.RawEncoder,
    ) -> _AeadClient:
        return cls._decode(encoded, encoder)


_AeadServer = TypeVar("_AeadServer", bound="AeadServer")


class AeadServer(_AeadKx, encoding.Encodable, StringFixer):
    """
    The AeadServer class boxes and unboxes messages between a pair of keys

    The ciphertexts generated by :class:`~nacl.public.AeadServer` include a 16
    byte authenticator which is checked as part of the decryption. An invalid
    authenticator will cause the decrypt function to raise an exception. The
    authenticator is not a signature. Once you've decrypted the message you've
    demonstrated the ability to create arbitrary valid message, so messages you
    send are repudiable. For non-repudiable messages, sign them after
    encryption.

    :param private_key: :class:`~nacl.public.PrivateKx` used to encrypt and
        decrypt messages
    :param public_key: :class:`~nacl.public.PublicKx` used to encrypt and
        decrypt messages

    :cvar NONCE_SIZE: The size that the nonce is required to be.
    """

    def _kx_session_keys(
        self, private_key: PrivateKx, public_key: PublicKx
    ) -> Tuple[bytes, bytes]:
        return nacl.bindings.crypto_kx_server_session_keys(
            private_key.public_key.encode(encoder=encoding.RawEncoder),
            private_key.encode(encoder=encoding.RawEncoder),
            public_key.encode(encoder=encoding.RawEncoder),
        )

    @classmethod
    def decode(
        cls: Type[_AeadServer],
        encoded: bytes,
        encoder: Encoder = encoding.RawEncoder,
    ) -> _AeadServer:
        return cls._decode(encoded, encoder)
