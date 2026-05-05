"""Post-build smoke test for PyNaCl wheels.

Shared by every wheel-builder job and ``ci.yml::pyemscripten`` so the
exercised code path stays identical across platforms.
"""

import nacl.signing


def main() -> None:
    key = nacl.signing.SigningKey.generate()
    signature = key.sign(b"smoketest")
    key.verify_key.verify(signature)
    print("OK: nacl.signing roundtrip succeeded")


if __name__ == "__main__":
    main()
