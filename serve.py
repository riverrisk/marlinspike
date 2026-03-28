"""Production-style launcher for local and installer deployments."""

import logging
import os

import _config as config


log = logging.getLogger("marlinspike.serve")


def _candidate_wireshark_dirs():
    candidates = []
    if config.WIRESHARK_BIN_DIR:
        candidates.append(config.WIRESHARK_BIN_DIR)
    if config.IS_WINDOWS:
        for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(env_name)
            if base:
                candidates.append(os.path.join(base, "Wireshark"))
    return [path for path in candidates if path and os.path.isdir(path)]


def _prime_runtime_path():
    existing = os.environ.get("PATH", "")
    parts = existing.split(os.pathsep) if existing else []
    updated = False
    for candidate in _candidate_wireshark_dirs():
        if candidate not in parts:
            parts.insert(0, candidate)
            updated = True
    if updated:
        os.environ["PATH"] = os.pathsep.join(parts)
        log.info("Prepended Wireshark tooling to PATH")


_prime_runtime_path()

from app import create_app  # noqa: E402


app = create_app()


if __name__ == "__main__":
    try:
        from waitress import serve
    except ImportError:
        log.warning("waitress not installed; falling back to Flask development server")
        app.run(host=config.HOST, port=config.PORT, debug=False)
    else:
        serve(app, host=config.HOST, port=config.PORT, threads=config.WSGI_THREADS)
