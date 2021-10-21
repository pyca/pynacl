import sys

if sys.version_info >= (3, 8):
    from typing import SupportsBytes
else:
    from typing_extensions import Protocol

    class SupportsBytes(Protocol):
        def __bytes__(self) -> bytes:
            pass


__all__ = ["SupportsBytes"]
