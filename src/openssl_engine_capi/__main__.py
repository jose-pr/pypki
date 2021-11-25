import argparse
from importlib import import_module
import inspect
import shutil
import site
import sysconfig
import os

MODULE_PATH = os.path.dirname(os.path.abspath(__file__))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Install .pth files which inject the WindowsSSLContext into urllib3 and pip"
    )
    parser.add_argument("command", choices=["inject", "extract"])
    parser.add_argument(
        "--user", help="Install or remove from user site-packages", action="store_true"
    )
    parser.add_argument(
        "--site_path",
        help="Install or remove inject_capi .pth and .py here instead of the user or system site-packages",
    )
    args = parser.parse_args()
    if args.site_path:
        site_path = args.site_path
    else:
        site_path = site.USER_SITE if args.user else sysconfig.get_paths()["purelib"]

    inject_script = os.path.join(MODULE_PATH, "~inject.py")
    dst = os.path.join(site_path, "inject_capi.py")
    if args.command == "inject":
        with open(inject_script, "r") as f:
            code = f.read()
        with open(dst, "w") as f:
            f.write(code)
            f.write(
                "\n".join(
                    [
                        'INJECT_INTO_MODULES = [  "urllib3", "pip._vendor.urllib3"]',
                        'INJECT_MODULE = "openssl_engine_capi.urllib3"',
                    ]
                )
            )
        import_module("inject_capi").install_pth()
    elif args.command == "extract" and os.path.exists(dst):
        os.remove(dst)
