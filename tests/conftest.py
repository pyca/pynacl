import sys

import pytest


def pytest_runtest_setup(item: pytest.Item) -> None:
    if sys.platform == "emscripten":
        for marker in item.iter_markers(name="skip_emscripten"):
            pytest.skip(
                marker.kwargs.get(
                    "reason", "Skipped under Emscripten/Pyodide"
                )
            )
