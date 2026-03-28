#!/usr/bin/env python3
"""Lightweight Windows desktop entrypoint for the bundled MarlinSpike app."""

from __future__ import annotations

import argparse
import os
import random
import runpy
import string
import sys
import threading
import time
import webbrowser
from pathlib import Path


PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*"


def _install_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _app_home() -> Path:
    configured = os.environ.get("MARLINSPIKE_HOME", "").strip()
    if configured:
        return Path(configured).expanduser()

    base = (
        os.environ.get("LOCALAPPDATA")
        or os.environ.get("LocalAppData")
        or os.environ.get("ProgramData")
        or str(_install_root())
    )
    return Path(base) / "MarlinSpike"


def _ensure_directories(app_home: Path) -> None:
    for rel in ("", "data", "logs", "run"):
        (app_home / rel).mkdir(parents=True, exist_ok=True)


def _admin_password(app_home: Path) -> str:
    password_file = app_home / "admin-password.txt"
    if password_file.exists():
        return password_file.read_text(encoding="utf-8").strip()

    password = "".join(random.SystemRandom().choice(PASSWORD_ALPHABET) for _ in range(20))
    password_file.write_text(password + "\n", encoding="utf-8")
    return password


def _wireshark_bin_dir() -> str:
    override = os.environ.get("WIRESHARK_BIN_DIR", "").strip()
    if override and Path(override).is_dir():
        return override

    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_name, "").strip()
        if not base:
            continue
        candidate = Path(base) / "Wireshark"
        if candidate.is_dir():
            return str(candidate)
    return ""


def _prime_environment(app_home: Path, port: int) -> None:
    os.environ["MARLINSPIKE_HOME"] = str(app_home)
    os.environ["MARLINSPIKE_DESKTOP_MODE"] = "true"
    os.environ["HOST"] = "127.0.0.1"
    os.environ["PORT"] = str(port)
    os.environ["SESSION_COOKIE_SECURE"] = "false"
    os.environ["ENABLE_LIVE_CAPTURE"] = "false"
    os.environ["ADMIN_PASSWORD"] = _admin_password(app_home)

    wireshark_dir = _wireshark_bin_dir()
    if wireshark_dir:
        os.environ["WIRESHARK_BIN_DIR"] = wireshark_dir
        existing_path = os.environ.get("PATH", "")
        path_parts = existing_path.split(os.pathsep) if existing_path else []
        if wireshark_dir not in path_parts:
            os.environ["PATH"] = wireshark_dir + (os.pathsep + existing_path if existing_path else "")


def _open_browser_later(port: int) -> None:
    def _target() -> None:
        time.sleep(2.0)
        webbrowser.open(f"http://127.0.0.1:{port}/")

    threading.Thread(target=_target, name="browser-open", daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", nargs="?", default="run", choices=("run", "open"))
    parser.add_argument("--port", type=int, default=5001)
    args = parser.parse_args()

    app_home = _app_home()
    _ensure_directories(app_home)
    _prime_environment(app_home, args.port)

    if args.mode == "open":
        _open_browser_later(args.port)

    install_root = _install_root()
    os.chdir(install_root)
    if str(install_root) not in sys.path:
        sys.path.insert(0, str(install_root))

    serve_py = install_root / "serve.py"
    runpy.run_path(str(serve_py), run_name="__main__")


if __name__ == "__main__":
    main()
