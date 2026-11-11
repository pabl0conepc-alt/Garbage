"""Runtime and operating-system diagnostics for supported source platforms."""

from __future__ import annotations

import platform
import sys


MINIMUM_PYTHON = (3, 10)


def runtime_diagnostics() -> dict[str, object]:
    system = platform.system()
    distribution = None
    if system == "Linux":
        try:
            distribution = platform.freedesktop_os_release().get("PRETTY_NAME")
        except OSError:
            pass

    return {
        "python": {
            "version": platform.python_version(),
            "minimum": ".".join(map(str, MINIMUM_PYTHON)),
            "supported": sys.version_info >= MINIMUM_PYTHON,
        },
        "platform": {
            "system": system or "unknown",
            "distribution": distribution,
            "supported": system in {"Windows", "Darwin", "Linux"},
        },
    }
