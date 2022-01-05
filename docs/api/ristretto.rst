nacl.ristretto
==============
.. currentmodule:: nacl.ristretto

The classes :py:class:`Ristretto255Scalar` and :py:class:`Ristretto255Point`
provide a high-level abstraction around the low-level bindings to `libsodium
<https://doc.libsodium.org/advanced/point-arithmetic/ristretto>`__.
Several functions are accessible through operator overloading.

See :ref:`finite-field-arithmetic` for high-level documentation.

.. autoclass:: Ristretto255Scalar
   :members:
   :special-members: __init__, __add__, __bool__, __bytes__, __eq__, __int__, __mul__, __truediv__, __neg__, __sub__


.. autoclass:: Ristretto255Point
   :members:
   :special-members: __add__, __bool__, __bytes__, __eq__, __mul__, __neg__, __sub__
