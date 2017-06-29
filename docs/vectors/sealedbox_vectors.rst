SealedBox reference vectors
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Since, at the time of writing, we haven't been able to find
reference vectors for the crypto_box_seal and the crypto_box_seal_open
APIs, the reference vectors used in testing have been generated using
a c-language driver

.. literalinclude:: c-source/sealbox_test_vectors.c
    :language: c
