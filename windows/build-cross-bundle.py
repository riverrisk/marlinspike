#!/usr/bin/env python3
"""Build a cross-platform Windows bundle using the embeddable Python distro."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
WINDOWS_DIR = REPO_ROOT / "windows"
BUILD_ROOT = WINDOWS_DIR / "build"
DOWNLOADS_DIR = BUILD_ROOT / "downloads"
WHEELS_DIR = BUILD_ROOT / "wheels"
BUNDLE_DIR = BUILD_ROOT / "bundle"

PAYLOAD = [
    "_auth.py",
    "_config.py",
    "_models.py",
    "_ms_engine.py",
    "app.py",
    "auth.py",
    "config.py",
    "models.py",
    "marlinspike.py",
    "serve.py",
    "requirements.txt",
    "LICENSE",
    "README.md",
    "templates",
    "static",
    "presets",
    "plugins",
    "rules",
]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--python-version", default="3.12.10")
    parser.add_argument(
        "--python-url",
        default="",
        help="Override the official embeddable Python download URL.",
    )
    parser.add_argument(
        "--app-version",
        default="",
        help="Override APP_VERSION instead of reading it from app.py.",
    )
    return parser.parse_args()


def app_version_from_source():
    app_py = (REPO_ROOT / "app.py").read_text(encoding="utf-8")
    marker = 'APP_VERSION = "'
    start = app_py.find(marker)
    if start == -1:
        return "dev"
    start += len(marker)
    end = app_py.find('"', start)
    return app_py[start:end] if end != -1 else "dev"


def python_embed_url(version: str) -> str:
    return f"https://www.python.org/ftp/python/{version}/python-{version}-embed-amd64.zip"


def download(url: str, dest: Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return
    print(f"[cross-bundle] Downloading {url}")
    with urllib.request.urlopen(url, timeout=60) as response, dest.open("wb") as handle:
        shutil.copyfileobj(response, handle)


def clean_build_dirs():
    if BUILD_ROOT.exists():
        shutil.rmtree(BUILD_ROOT)
    DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
    WHEELS_DIR.mkdir(parents=True, exist_ok=True)
    BUNDLE_DIR.mkdir(parents=True, exist_ok=True)


def extract_embed_runtime(zip_path: Path, python_version: str):
    python_dir = BUNDLE_DIR / "python"
    python_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as archive:
        archive.extractall(python_dir)

    major, minor, *_rest = python_version.split(".")
    pth_path = python_dir / f"python{major}{minor}._pth"
    lines = []
    if pth_path.exists():
        lines = [line.strip() for line in pth_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    output = []
    saw_site_packages = False
    for line in lines:
        if line.lstrip().startswith("#"):
            continue
        if line == "import site":
            continue
        output.append(line)
        if line == "Lib\\site-packages":
            saw_site_packages = True
    if not saw_site_packages:
        output.append("Lib\\site-packages")
    if "." not in output:
        output.append(".")
    output.append("import site")
    pth_path.write_text("\r\n".join(output) + "\r\n", encoding="utf-8")

    return python_dir


def download_windows_wheels():
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--only-binary=:all:",
        "--platform",
        "win_amd64",
        "--python-version",
        "312",
        "--implementation",
        "cp",
        "--dest",
        str(WHEELS_DIR),
        "-r",
        str(REPO_ROOT / "requirements.txt"),
    ]
    print("[cross-bundle] Downloading Windows wheels")
    subprocess.run(cmd, check=True)


def unpack_wheel(wheel_path: Path, site_packages: Path):
    with zipfile.ZipFile(wheel_path) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            name = member.filename
            target_rel = name
            if ".data/" in name:
                _, data_rel = name.split(".data/", 1)
                if data_rel.startswith("purelib/") or data_rel.startswith("platlib/"):
                    target_rel = data_rel.split("/", 1)[1]
                else:
                    continue
            target_path = site_packages / Path(target_rel)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as src, target_path.open("wb") as dst:
                shutil.copyfileobj(src, dst)


def install_wheels(python_dir: Path):
    site_packages = python_dir / "Lib" / "site-packages"
    site_packages.mkdir(parents=True, exist_ok=True)
    for wheel_path in sorted(WHEELS_DIR.glob("*.whl")):
        print(f"[cross-bundle] Unpacking {wheel_path.name}")
        unpack_wheel(wheel_path, site_packages)


def copy_payload():
    for item in PAYLOAD:
        source = REPO_ROOT / item
        if not source.exists():
            continue
        destination = BUNDLE_DIR / item
        if source.is_dir():
            shutil.copytree(source, destination, dirs_exist_ok=True)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    shutil.copytree(WINDOWS_DIR / "runtime", BUNDLE_DIR / "runtime", dirs_exist_ok=True)


def write_version(app_version: str):
    (BUNDLE_DIR / "VERSION.txt").write_text(app_version + "\n", encoding="ascii")


def main():
    args = parse_args()
    clean_build_dirs()

    app_version = args.app_version or app_version_from_source()
    version = args.python_version
    embed_url = args.python_url or python_embed_url(version)
    embed_zip = DOWNLOADS_DIR / Path(embed_url).name

    download(embed_url, embed_zip)
    python_dir = extract_embed_runtime(embed_zip, version)
    download_windows_wheels()
    install_wheels(python_dir)
    copy_payload()
    write_version(app_version)

    print(f"[cross-bundle] Bundle ready at {BUNDLE_DIR}")


if __name__ == "__main__":
    main()
