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
import shutil
import hashlib

logger = logging.getLogger(__file__)
logging.basicConfig(level=logging.INFO)


def run_with_logging(cmd, cwd, log_dir, log_prefix):
    """Run subprocess with stdout/stderr redirected to log files."""
    stdout_path = log_dir / f"{log_prefix}.stdout"
    stderr_path = log_dir / f"{log_prefix}.stderr"

    with open(stdout_path, "w") as stdout_file, open(stderr_path, "w") as stderr_file:
        return subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            stdout=stdout_file,
            stderr=stderr_file,
        )


def verify_openssl(version="3.5.2"):
    """Verify OpenSSL installation."""
    Path("vendor/src").mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/openssl/openssl/releases/download/openssl-{version}/openssl-{version}.tar.gz.sha256"
    dest = Path(f"vendor/src/openssl-{version}.tar.gz.sha256")
    if dest.exists():
        if dest.is_file():
            dest.unlink()
        else:
            shutil.rmtree(dest)
    urllib.request.urlretrieve(url, dest)
    expected_sha256sum = dest.read_text().strip()
    dest = Path(f"vendor/src/openssl-{version}.tar.gz")
    if not dest.exists():
        return False
    if not dest.is_file():
        return False
    hash_sha256 = hashlib.sha256()
    with open(dest, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    actual_sha256sum = hash_sha256.hexdigest()
    if actual_sha256sum != expected_sha256sum.split()[0]:
        return False
    return True


def download_openssl(version="3.5.2"):
    """Download OpenSSL source code."""
    url = f"https://github.com/openssl/openssl/releases/download/openssl-{version}/openssl-{version}.tar.gz"
    dest = Path(f"vendor/src/openssl-{version}.tar.gz")
    if dest.exists():
        if dest.is_file():
            dest.unlink()
        else:
            shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, dest)
    logger.info(f"Downloaded OpenSSL {version} to {dest}")


def extract_openssl(version="3.5.2"):
    """Extract OpenSSL source code."""
    tar_path = Path(f"vendor/src/openssl-{version}.tar.gz")
    if not tar_path.exists():
        raise FileNotFoundError(f"OpenSSL tarball {tar_path} does not exist.")

    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(path="vendor/src")


def build_openssl(version="3.5.2"):
    """Build OpenSSL from source."""
    openssl_path = Path(f"vendor/src/openssl-{version}")
    if not openssl_path.exists():
        raise FileNotFoundError(
            f"OpenSSL source directory {openssl_path} does not exist."
        )

    log_dir = Path("vendor/log/openssl")
    log_dir.mkdir(parents=True, exist_ok=True)

    if platform.system() == "Windows":
        if platform.architecture()[0] == "64bit":
            run_with_logging(
                [
                    "perl",
                    "Configure",
                    "VC-WIN64A",
                    f"--prefix={Path('vendor').resolve()}",
                    f"--openssldir={Path.home() / '.moon' / 'ssl'}",
                    f"no-docs",
                    f"no-shared",
                ],
                cwd=openssl_path,
                log_dir=log_dir,
                log_prefix="configure",
            )
        else:
            run_with_logging(
                [
                    "perl",
                    "Configure",
                    "VC-WIN32",
                    f"--prefix={Path('vendor').resolve()}",
                    f"--openssldir={Path.home() / '.moon' / 'ssl'}",
                    f"no-docs",
                    f"no-shared",
                ],
                cwd=openssl_path,
                log_dir=log_dir,
                log_prefix="configure",
            )
    else:
        run_with_logging(
            [
                "perl",
                "Configure",
                f"--prefix={Path('vendor').resolve()}",
                f"--openssldir={Path.home() / '.moon' / 'ssl'}",
                f"no-docs",
                f"no-shared",
            ],
            cwd=openssl_path,
            log_dir=log_dir,
            log_prefix="configure",
        )

    logger.info("Building OpenSSL...")
    if platform.system() == "Windows":
        run_with_logging(
            ["nmake"],
            cwd=openssl_path,
            log_dir=log_dir,
            log_prefix="build",
        )
    else:
        cpu_count = os.cpu_count() or 4
        run_with_logging(
            ["make", "-j", str(cpu_count)],
            cwd=openssl_path,
            log_dir=log_dir,
            log_prefix="build",
        )

    logger.info("Installing OpenSSL...")
    if platform.system() == "Windows":
        run_with_logging(
            ["nmake", "install"],
            cwd=openssl_path,
            log_dir=log_dir,
            log_prefix="install",
        )
    else:
        run_with_logging(
            ["make", "install"],
            cwd=openssl_path,
            log_dir=log_dir,
            log_prefix="install",
        )


def openssl_is_built():
    if platform.system() == "Windows":
        return (
            Path("vendor/lib/libssl.lib").exists()
            and Path("vendor/lib/libcrypto.lib").exists()
        )
    elif platform.system() == "Linux":
        return (
            Path("vendor/lib64/libssl.a").exists()
            and Path("vendor/lib64/libcrypto.a").exists()
        )
    elif platform.system() == "Darwin":
        return (
            Path("vendor/lib/libssl.a").exists()
            and Path("vendor/lib/libcrypto.a").exists()
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
    version = "3.5.2"
    if not verify_openssl(version=version):
        logger.warning("Failed to verify the integrity of OpenSSL, re-downloading...")
        download_openssl(version=version)
    if not openssl_is_built():
        logger.info("OpenSSL is not built, extracting and building...")
        extract_openssl(version=version)
        build_openssl(version=version)
    link_flags = []
    link_libs = []
    link_search_paths = []
    if platform.system() == "Windows":
        link_libs.append(str((vendor / "lib").resolve() / "libssl"))
        link_libs.append(str((vendor / "lib").resolve() / "libcrypto"))
    elif platform.system() == "Darwin":
        link_libs.append("ssl")
        link_libs.append("crypto")
        link_search_paths.append(str((vendor / "lib").resolve()))
    elif platform.system() == "Linux":
        link_libs.append("ssl")
        link_libs.append("crypto")
        link_search_paths.append(str((vendor / "lib64").resolve()))
    else:
        raise NotImplementedError(f"Unsupported platform: {platform.system()}")
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
    cc_flags = []
    include_directory = Path("vendor/include").resolve()
    if platform.system() == "Windows":
        cc_flags.append(f"/I{include_directory}")
    else:
        cc_flags.append(f"-I{include_directory}")
    output = json.dumps(
        {
            "vars": {
                "CC": cc,
                "CC_FLAGS": " ".join(cc_flags),
            },
            "link_configs": [
                {
                    "package": "tonyfettes/openssl",
                    "link_flags": " ".join(link_flags),
                    "link_libs": link_libs,
                    "link_search_paths": link_search_paths,
                }
            ],
        }
    )
    sys.stdout.write(output)


if __name__ == "__main__":
    main()
