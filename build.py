#!/usr/bin/env python3

import sys
import json
import urllib.request
from pathlib import Path
import subprocess
import platform
import tarfile
import logging
import argparse
import os

logger = logging.getLogger(__file__)
logging.basicConfig(level=logging.INFO)


def download_openssl(version="3.5.1"):
    """Download OpenSSL source code."""
    url = f"https://github.com/openssl/openssl/releases/download/openssl-3.5.1/openssl-3.5.1.tar.gz"
    dest = Path("vendor/src/openssl-3.5.1.tar.gz")
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, dest)


def extract_openssl():
    """Extract OpenSSL source code."""
    tar_path = Path("vendor/src/openssl-3.5.1.tar.gz")
    if not tar_path.exists():
        raise FileNotFoundError(f"OpenSSL tarball {tar_path} does not exist.")

    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(path="vendor/src")


def build_openssl():
    """Build OpenSSL from source."""
    openssl_path = Path("vendor/src/openssl-3.5.1")
    if not openssl_path.exists():
        raise FileNotFoundError(
            f"OpenSSL source directory {openssl_path} does not exist."
        )

    log_dir = Path("vendor/log/openssl")
    log_dir.mkdir(parents=True, exist_ok=True)

    configure = subprocess.run(
        [
            "perl",
            "Configure",
            f"--prefix={Path('vendor/lib').resolve()}",
            f"--openssldir={Path.home() / '.moon' / 'ssl'}",
            f"no-docs",
        ],
        cwd=openssl_path,
        check=True,
        capture_output=True,
    )
    (log_dir / "configure.stdout").write_bytes(configure.stdout)
    (log_dir / "configure.stderr").write_bytes(configure.stderr)

    logger.info("Building OpenSSL...")
    if platform.system() == "Windows":
        nmake = subprocess.run(
            ["nmake"],
            cwd=openssl_path,
            check=True,
            capture_output=True,
        )
        (log_dir / "build.stdout").write_bytes(nmake.stdout)
        (log_dir / "build.stderr").write_bytes(nmake.stderr)
    else:
        cpu_count = os.cpu_count() or 4
        make = subprocess.run(
            ["make", "-j", str(cpu_count)],
            cwd=openssl_path,
            check=True,
            capture_output=True,
        )
        (log_dir / "build.stdout").write_bytes(make.stdout)
        (log_dir / "build.stderr").write_bytes(make.stderr)

    logger.info("Installing OpenSSL...")
    if platform.system() == "Windows":
        nmake = subprocess.run(
            ["nmake", "install"], cwd=openssl_path, check=True, capture_output=True
        )
        (log_dir / "install.stdout").write_bytes(nmake.stdout)
        (log_dir / "install.stderr").write_bytes(nmake.stderr)
    else:
        make = subprocess.run(
            ["make", "install"], cwd=openssl_path, check=True, capture_output=True
        )
        (log_dir / "install.stdout").write_bytes(make.stdout)
        (log_dir / "install.stderr").write_bytes(make.stderr)


def openssl_is_built():
    if platform.system() == "Windows":
        return (
            Path("vendor/lib/libssl.lib").exists()
            and Path("vendor/lib/libcrypto.lib").exists()
        )
    elif platform.system() == "Linux":
        return (
            Path("vendor/lib/libssl.so").exists()
            and Path("vendor/lib/libcrypto.so").exists()
        )
    elif platform.system() == "Darwin":
        return (
            Path("vendor/lib/libssl.dylib").exists()
            and Path("vendor/lib/libcrypto.dylib").exists()
        )
    else:
        raise NotImplementedError(f"Unsupported platform: {platform.system()}")


def main():
    parser = argparse.ArgumentParser(description="Build OpenSSL for MoonBit")
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Run the build script manually without reading from stdin",
    )
    args = parser.parse_args()
    env = os.environ.copy()
    if args.manual is False:
        """Simple cat that reads from stdin and saves content to build.input"""
        text = sys.stdin.read()
        data = json.loads(text)
        env = data
    moon_home = None
    if "MOON_HOME" in env:
        moon_home = env["MOON_HOME"]
    else:
        moon_home = Path.home() / ".moon"
    moon_home = Path(moon_home)
    if not moon_home.exists():
        raise FileNotFoundError(f"MOON_HOME directory {moon_home} does not exist.")
    vendor = Path("vendor")
    if not openssl_is_built():
        download_openssl()
        extract_openssl()
        build_openssl()
    link_libs = ["crypto", "ssl"]
    link_search_paths = [
        str((vendor / "lib").resolve()),
    ]
    cc = None
    if "CC" in env:
        cc = env["CC"]
    else:
        if platform.system() == "Windows":
            cc = "cl"
        elif platform.system() == "Darwin":
            cc = "clang"
        else:
            cc = "gcc"
    output = json.dumps(
        {
            "vars": {
                "CC": cc,
            },
            "link_configs": [
                {
                    "package": "tonyfettes/openssl",
                    "link_libs": link_libs,
                    "link_search_paths": link_search_paths,
                }
            ],
        }
    )
    sys.stdout.write(output)


if __name__ == "__main__":
    main()
