import argparse
from importlib import import_module
import site
import sysconfig
import os, sys
import json

MODULE_PATH = os.path.dirname(os.path.abspath(__file__))
MODULE_NAME = MODULE_PATH.split(os.path.sep)[-1]
sys.path.insert(0,  os.path.abspath(MODULE_PATH+"/.."))
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"Install .pth files which inject"
    )
    parser.add_argument("command", choices=["inject", "extract"])
    parser.add_argument("--module", default=MODULE_NAME)
    parser.add_argument("--into", default=None)
    parser.add_argument(
        "--user", help="Install or remove from user site-packages", action="store_true"
    )
    parser.add_argument(
        "--site_path",
        help="Install or remove .pth and .py here instead of the user or system site-packages",
    )
    args = parser.parse_args()
    if args.site_path:
        site_path = args.site_path
    else:
        site_path = site.USER_SITE if args.user else sysconfig.get_paths()["purelib"]

    INJECT_MODULE = args.module
    module = import_module(INJECT_MODULE)
    INJECT_INTO_MODULES = getattr(module, "INJECT_INTO_MODULES", [])

    inject_script = os.path.join(MODULE_PATH, "~inject.py")
    inject_module = f'inject_{INJECT_MODULE}_into_{"_".join(INJECT_INTO_MODULES)}'
    base_file = inject_module.replace()
    dst = os.path.join(site_path, f"{inject_module}.py")

    print(f"Inject Module:{INJECT_MODULE} into {', '.join(INJECT_INTO_MODULES)}")
    print(f"File Base Name: {inject_module}")
    if args.command == "inject":
        if not hasattr(module, 'inject_into'):
            exit()
        with open(inject_script, "r") as f:
            code = f.read()
        with open(dst, "w") as f:
            f.write(code)

            f.write(
                "\n".join(
                    [
                        f"{var}={json.dumps(globals()[var])}"
                        for var in ["INJECT_MODULE", "INJECT_INTO_MODULES"]
                    ]
                )
            )
        import_module(inject_module).install_pth()
    elif args.command == "extract" and os.path.exists(dst):
        os.remove(dst)
