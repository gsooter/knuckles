"""Structured logging setup for Knuckles."""

import logging
import sys


def setup_logging(*, debug: bool = False) -> None:
    """Configure application-wide structured logging.

    Args:
        debug: If True, set log level to DEBUG. Otherwise INFO.
    """
    level = logging.DEBUG if debug else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)

    root_logger = logging.getLogger("knuckles")
    root_logger.setLevel(level)
    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger under the ``knuckles`` namespace.

    Args:
        name: Logger name, typically the caller's ``__name__``.

    Returns:
        A configured ``logging.Logger`` instance.
    """
    return logging.getLogger(f"knuckles.{name}")
