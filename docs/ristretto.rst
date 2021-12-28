.. currentmodule:: nacl.ristretto
.. _finite-field-arithmetic:

Finite field arithmetic
=======================
`Ristretto255 <https://ristretto.group/>`__ is a prime order elliptic curve
group based on Curve25519. It can be used as a building block for cryptographic
protocols such as `Zero-knowledge proofs of knowledge
<https://en.wikipedia.org/wiki/Zero-knowledge_proof>`__,
`ElGamal encryption <https://en.wikipedia.org/wiki/ElGamal_encryption>`__ or
`Schnorr signatures <https://en.wikipedia.org/wiki/Schnorr_signature>`__.


Two high-level classes are defined to wrap the `libsodium
<https://doc.libsodium.org/advanced/point-arithmetic/ristretto>`__ API:

* :py:class:`Ristretto255Scalar` is the `finite field
  <https://en.wikipedia.org/wiki/Finite_field>`__ over the set of integers
  modulo the prime ``2 ** 252 + 27742317777372353535851937790883648493`` and
  the four operations *addition*, *subtraction*, *multiplication* and
  *division*. Each operation takes two elements from the set and computes
  another element from the same set. Most operations are accessible through
  operator overloading.

* :py:class:`Ristretto255Point` is the `cyclic group
  <https://en.wikipedia.org/wiki/Cyclic_group>`__ with points from the
  Curve25519 elliptic curve. Thanks to the Ristretto construction, all elements
  in the group are unique, and each element (other than the identity) is a
  generator of the complete group. The order of :py:class:`Ristretto255Scalar`
  matches this group's order. The basic operation in the group is *point
  addition*. Repeated addition of the same point is called `multiplicaton
  <https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication>`__.

An `isomorphism <https://en.wikipedia.org/wiki/Isomorphism>`__ exists between
the two groups. This means that for scalars ``s, t`` and a point ``p``
equations such as this hold: ``p * (s + t) == (p * s) + (p * t)``.


Scalar field
------------
Each instance of :py:class:`Ristretto255Scalar` is a scalar value (integer
reduced modulo the group order). The internal representation is a 32 byte array
in little-endian order.

The operators and methods support arguments of various python types. They are
automatically reduced modulo the group order and converted into the internal
representation.

* Another :py:class:`Ristretto255Scalar`
* :py:class:`bytes`, an 32 byte integer in little-endian encoding.
* :py:class:`int`, an arbitrary integer.
* :py:class:`fractions.Fraction`.

Argument types can be mixed:

.. testcode::

    from fractions import Fraction
    from nacl.ristretto import Ristretto255Scalar

    r = Ristretto255Scalar(42) / 11 * Fraction(5, 7) * (b"\x21" + bytes(31)) - -10
    print(int(r))

.. testoutput::

    100

Following table shows how to translate from libsodium functions:

.. list-table:: Translating from libsodium to Ristretto255Scalar
   :header-rows: 1
   :widths: auto

   * - `libsodium <https://doc.libsodium.org/advanced/point-arithmetic/ristretto#scalar-arithmetic-over-l>`__
     - PyNaCl

   * - ``crypto_core_ristretto255_nonreducedscalarbytes()``
     - :py:attr:`Ristretto255Scalar.NONREDUCED_SIZE`

   * - ``crypto_core_ristretto255_scalarbytes()``
     - :py:attr:`Ristretto255Scalar.SIZE`

   * - ``crypto_core_ristretto255_scalar_random(u)``
     - :py:meth:`u = Ristretto255Scalar.random() <Ristretto255Scalar.random>`

   * - ``crypto_core_ristretto255_scalar_reduce(u, h)``
     - :py:meth:`u = Ristretto255Scalar.reduce(h) <Ristretto255Scalar.reduce>`

   * - ``crypto_core_ristretto255_scalar_invert(u, s)``
     - :py:attr:`u = s.inverse <Ristretto255Scalar.inverse>`

   * - ``crypto_core_ristretto255_scalar_complement(u, s)``
     - :py:attr:`u = s.complement <Ristretto255Scalar.complement>`

   * - ``crypto_core_ristretto255_scalar_add(u, s, t)``
     - :py:meth:`u = s + t <Ristretto255Scalar.__add__>`

   * - ``crypto_core_ristretto255_scalar_sub(u, s, t)``
     - :py:meth:`u = s - t <Ristretto255Scalar.__sub__>`

   * - ``crypto_core_ristretto255_scalar_mul(u, s, t)``
     - :py:meth:`u = s * t <Ristretto255Scalar.__mul__>`

   * - ``crypto_core_ristretto255_scalar_mul(u, s, t.inverse)``
     - :py:meth:`u = s / t <Ristretto255Scalar.__truediv__>`

   * - ``crypto_core_ristretto255_scalar_negate(u, s)``
     - :py:meth:`u = -s <Ristretto255Scalar.__neg__>`

   * - ``sodium_memcmp(s, t, 32)``
     - :py:meth:`s == t <Ristretto255Scalar.__eq__>`

   * - ``sodium_is_zero(s, 32)``
     - :py:meth:`bool(s) <Ristretto255Scalar.__bool__>`

Ristretto group
---------------
The multiplication operators take a scalar as operand which must be one of the
types from above list. All other operands and arguments must be points.

Argument types can be mixed:

.. testcode::

    from fractions import Fraction
    from nacl.ristretto import Ristretto255Point, Ristretto255Scalar

    p = Ristretto255Point.random()
    q = (p * Fraction(5, 7) - p) * Ristretto255Scalar(7)
    print(bytes(p * 2 + q).hex())


.. testoutput::

    0000000000000000000000000000000000000000000000000000000000000000


Following table shows how to translate from libsodium functions:

.. list-table:: Translating from libsodium to Ristretto255Point
   :header-rows: 1
   :widths: auto

   * - `libsodium <https://doc.libsodium.org/advanced/point-arithmetic/ristretto>`__
     - PyNaCl

   * - ``crypto_core_ristretto255_bytes()``
     - :py:attr:`Ristretto255Point.SIZE`

   * - ``crypto_core_ristretto255_hashbytes()``
     - :py:attr:`Ristretto255Point.HASH_SIZE`

   * - ``crypto_core_ristretto255_is_valid_point(p)``
     - :py:meth:`r = Ristretto255Point(p) <Ristretto255Point.__init__>`

   * - ``crypto_core_ristretto255_from_hash(r, h)``
     - :py:meth:`r = Ristretto255Point.from_hash(h) <Ristretto255Point.from_hash>`

   * - ``crypto_core_ristretto255_random(r)``
     - :py:meth:`r = Ristretto255Point.random() <Ristretto255Point.random>`

   * - ``crypto_scalarmult_ristretto255_base(r, s)``
     - :py:meth:`r = Ristretto255Point.base_mul(s) <Ristretto255Point.base_mul>`

   * - ``crypto_scalarmult_ristretto255(r, -1, p)``
     - :py:meth:`r = -p <Ristretto255Point.__neg__>`

   * - ``crypto_core_ristretto255_add(r, p, q)``
     - :py:meth:`r = p + q <Ristretto255Point.__add__>`

   * - ``crypto_core_ristretto255_sub(r, p, q)``
     - :py:meth:`r = p - q <Ristretto255Point.__sub__>`

   * - ``crypto_scalarmult_ristretto255(r, s, p)``
     - :py:meth:`r = p * s <Ristretto255Point.__mul__>`

   * - ``sodium_memcmp(p, q, 32)``
     - :py:meth:`p == q <Ristretto255Point.__eq__>`

   * - ``sodium_is_zero(p, 32)``
     - :py:meth:`bool(p) <Ristretto255Point.__bool__>`


Examples
--------
There are two code examples for `ElGamal encryption
<https://en.wikipedia.org/wiki/ElGamal_encryption>`__ and `Shamir's Secret
Sharing <https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing>`__ in the
test cases. Two simpler examples follow:

Secure two-party computation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This is the example from `libsodium
<https://doc.libsodium.org/advanced/point-arithmetic/ristretto>`__:

.. testcode::

    from os import urandom
    from nacl.ristretto import Ristretto255Point, Ristretto255Scalar

    ## First party: Send blinded p(x) ##
    x = urandom(Ristretto255Point.HASH_SIZE)

    # Compute px = p(x), a group element derived from x
    px = Ristretto255Point.from_hash(x)

    # Compute a = p(x) * g^r
    r = Ristretto255Scalar.random()
    gr = Ristretto255Point.base_mul(r)
    a = px + Ristretto255Point.base_mul(r)


    ## Second party: Send g^k and a^k ##
    k = Ristretto255Scalar.random()

    # Compute v = g^k
    v = Ristretto255Point.base_mul(k)

    # Compute b = a^k
    b = a * k


    ## First party: Unblind f(x) ##

    # Compute f(x) = b * v^(-r)
    #              = (p(x) * g^r)^k * (g^k)^(-r)
    #              = (p(x) * g)^k * g^(-k)
    #              = p(x)^k
    fx = b - v * r

    # Compare result
    print(px * k == fx)

.. testoutput::

    True

Schnorr signature
~~~~~~~~~~~~~~~~~
The `Schnorr signature <https://en.wikipedia.org/wiki/Schnorr_signature>`__
scheme can adopted to use Ristretto255:

.. testcode::

    from nacl.ristretto import Ristretto255Point, Ristretto255Scalar
    import hashlib


    ## Choosing parameters ##

    # Agree on group of prime order
    G = Ristretto255Point

    # Choose a random generator
    g = G.random()

    # Agree on a cryptographic hash function; needs to have 512 bits output
    H = lambda data: Ristretto255Scalar.reduce(hashlib.sha3_512(data).digest())


    ## Key generation ##

    # Choose a private signing key
    x = Ristretto255Scalar.random()

    # Compute the public verification key
    y = g * x


    ## Signing ##

    # Message to sign
    M = b"Lorem ipsum dolor sit amet"

    # Choose a random nonce
    k = Ristretto255Scalar.random()

    # Computate the signature
    r = g * k
    e = H(bytes(r) + M)
    s = k - x * e

    # Signature is the scalars (s, e)


    ## Verifying ##

    r_v = g * s + y * e
    e_v = H(bytes(r_v) + M)

    if e_v == e:
        print("Signature verified")


    ## Key leakage from nonce reuse ##

    # Another message to sign
    M_ = b"consectetur adipiscing elit"

    # Reuse nonce. Don't do that!
    k_ = k

    # Computate the signature
    r_ = g * k_
    e_ = H(bytes(r_) + M_)
    s_ = k_ - x * e_

    # Compute private key
    x_ = (s_ - s) / (e - e_)

    if g * x_ == y:
        print("Key was leaked")

.. testoutput::

    Signature verified
    Key was leaked
