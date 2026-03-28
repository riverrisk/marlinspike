"""Bootstrap package for the future standalone marlinspike-msengine repo."""

__all__ = ["main"]


def main():
    """Lazy package entrypoint that delegates to the mirrored engine module."""
    from .engine import main as engine_main

    engine_main()
