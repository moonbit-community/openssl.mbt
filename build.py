#!/usr/bin/env python3

import sys
import json
import urllib.request
from pathlib import Path
import subprocess
import platform
import tarfile


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

    subprocess.run(
        [
            "perl",
            "Configure",
            f"--prefix={Path('vendor/lib').resolve()}",
            f"--openssldir={Path.home() / '.moon' / 'ssl'}",
        ],
        cwd=openssl_path,
        check=True,
    )

    if platform.system() == "Windows":
        subprocess.run(["nmake"], cwd=openssl_path, check=True)
    else:
        subprocess.run(["make", "-j", "4"], cwd=openssl_path, check=True)

    if platform.system() == "Windows":
        subprocess.run(["nmake", "install"], cwd=openssl_path, check=True)
    else:
        subprocess.run(["make", "install"], cwd=openssl_path, check=True)


def main():
    """Simple cat that reads from stdin and saves content to build.input"""
    text = sys.stdin.read()
    data = json.loads(text)
    moon_home = None
    if "MOON_HOME" in data["env"]:
        moon_home = data["env"]["MOON_HOME"]
    else:
        moon_home = Path.home() / ".moon"
    moon_home = Path(moon_home)
    if not moon_home.exists():
        raise FileNotFoundError(f"MOON_HOME directory {moon_home} does not exist.")
    vendor = Path("vendor")
    if not (vendor / "lib" / "libssl.dylib").exists():
        download_openssl()
        extract_openssl()
        build_openssl()
    link_libs = ["crypto", "ssl"]
    link_search_paths = [
        str((vendor / "lib").resolve()),
    ]
    cc = None
    if "CC" in data["env"]:
        cc = data["env"]["CC"]
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
