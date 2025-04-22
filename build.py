import subprocess
from pathlib import Path
import platform
import os
import shutil


MOON_HOME = os.getenv("MOON_HOME")
if MOON_HOME is None:
    moon_home = Path.home() / ".moon"
else:
    moon_home = Path(MOON_HOME)


def main():
    openssl_directory = Path("openssl")
    subprocess.run(["perl", "Configure"], check=True, cwd=openssl_directory)
    if platform.system() == "Windows":
        subprocess.run(["nmake"], check=True, cwd=openssl_directory)
    else:
        subprocess.run(["make"], check=True, cwd=openssl_directory)
    if platform.system() == "Windows":
        pass
    else:
        shutil.copyfile(openssl_directory / "libssl.a", moon_home / "lib" / "libssl.a")


if __name__ == "__main__":
    main()
