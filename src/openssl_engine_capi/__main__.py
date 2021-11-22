import argparse
import inspect
import shutil
import site
import sysconfig
import os

MODULE_PATH = os.path.dirname(os.path.abspath(__file__))

def pth_import_fn():
    import importlib, os, atexit
    from importlib.util import find_spec
    importlib.import_module("inject_capi").inject() if find_spec("inject_capi") else None
    atexit.register( lambda file=locals().get("fullname"): os.remove(file) if file and not os.path.exists(os.path.join(os.path.dirname(file),"inject_capi.py")) and os.path.exists(file) else None) 
        

def remove(path:str):
    if os.path.exists(path):
        os.remove(path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'Install .pth files which inject the WindowsSSLContext into urllib3 and pip')
    parser.add_argument('--user', help='Install or remove from user site-packages', action="store_true")
    parser.add_argument("--site_path", help="Install or remove inject_capi .pth and .py here instead of the user or system site-packages")
    parser.add_argument("--remove", help="Remove inject script instead of installing them", action="store_true")
    args = parser.parse_args()
    if args.site_path:
        site_path = args.site_path
    else:
        site_path = site.USER_SITE if args.user else sysconfig.get_paths()["purelib"]
    inject_script = os.path.join(MODULE_PATH, "_inject_capi.py")
    dst = os.path.join(site_path, "inject_capi.py")
    pth_path = os.path.join(site_path, "inject_capi.pth")

    remove(dst)
    remove(pth_path)
    if not args.remove:
        shutil.copy(inject_script, dst)
        with open(pth_path, "w") as pth:
            pth.write(";".join(inspect.getsource(pth_import_fn).splitlines()[1:]).strip())
