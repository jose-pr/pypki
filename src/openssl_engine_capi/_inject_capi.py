import atexit
from importlib.util import spec_from_file_location, find_spec
import os
import sys
from importlib.abc import MetaPathFinder
from importlib.machinery import SourceFileLoader
import types


INJECT_INTO_MODULES = ["urllib3", "pip"]


class CapiUrllib3InjectLoader(SourceFileLoader):
    def exec_module(self, module: types.ModuleType) -> None:
        super().exec_module(module)
        if find_spec("openssl_engine_capi.urllib3"):
            from openssl_engine_capi import urllib3 as capi_urllib3
            capi_urllib3.inject_into_urllib3(module.__name__)


class CapiUrllib3InjectFinder(MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname in INJECT_INTO_MODULES:
            if path is None or path == "":
                path = sys.path  # top level import --
            if "." in fullname:
                *parents, name = fullname.split(".")
            else:
                name = fullname
            for entry in path:
                if os.path.isdir(os.path.join(entry, name)):
                    filename = os.path.join(entry, name, "__init__.py")
                    submodule_locations = [os.path.join(entry, name)]
                else:
                    filename = os.path.join(entry, name + ".py")
                    submodule_locations = None
                if not os.path.exists(filename):
                    continue
                return spec_from_file_location(
                    fullname,
                    filename,
                    loader=CapiUrllib3InjectLoader(fullname, filename),
                    submodule_search_locations=submodule_locations,
                )
        return None


def inject():
    sys.meta_path.insert(0, CapiUrllib3InjectFinder())


def remove(path: str):
    if os.path.exists(path):
        os.remove(path)


def cleanup():
    if not find_spec("openssl_engine_capi"):
        remove(__file__)
        remove(os.path.join(os.path.dirname(__file__), "inject_capi.pth"))


atexit.register(cleanup)
