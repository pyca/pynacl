from . import __about__
from . import hash  # pylint: disable=W0622


__all__ = ["hash"] + __about__.__all__


# - Meta Information -
# This is pretty ugly
for attr in __about__.__all__:
    if hasattr(__about__, attr):
        globals()[attr] = getattr(__about__, attr)
# - End Meta Information -
