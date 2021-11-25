import atexit
import importlib
from importlib.util import spec_from_file_location, find_spec
import inspect
import os
import sys
from importlib.abc import MetaPathFinder
from importlib.machinery import SourceFileLoader
import types

INJECT_INTO_MODULES = []
INJECT_MODULE = ""

PTH_PATH = __file__.removesuffix(".py") + ".pth"

class InjectIntoLoader(SourceFileLoader):
    def __init__(self, fullname: str, path, module) -> None:
        super().__init__(fullname, path)
        self.module = module

    def exec_module(self, module: types.ModuleType) -> None:
        super().exec_module(module)
        inject_spec = find_spec(self.module)
        if inject_spec:
            importlib.import_module(self.module).inject_into(module.__name__)


class InjectIntoFinder(MetaPathFinder):
    def __init__(self, module: str, into: list[str]) -> None:
        super().__init__()
        self.module = module
        self.into = into

    def find_spec(self, fullname, path, target=None):
        if fullname in self.into:
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
                    loader=InjectIntoLoader(fullname, filename, self.module),
                    submodule_search_locations=submodule_locations,
                )
        return None


def inject():
    if INJECT_MODULE:
        sys.meta_path.insert(0, InjectIntoFinder(INJECT_MODULE, INJECT_INTO_MODULES))
    atexit.register(lambda: cleanup(INJECT_MODULE))


def remove(path: str):
    if os.path.exists(path):
        os.remove(path)


def cleanup(module: str):
    if not module or not find_spec(module):
        remove(__file__)
        remove(PTH_PATH)

def __pth_import_fn(file:str):
    import importlib, os, atexit
    from importlib.util import find_spec
    __filename=locals().get("fullname", None)
    __module=os.path.basename(__filename).removesuffix(".pth")
    __spec=find_spec(__module)
    importlib.import_module(__module).inject() if __spec else None
    atexit.register( lambda file=__filename: os.remove(file) if file and not os.path.exists(file.removesuffix(".pth")+".py") and os.path.exists(file) else None) 

def install_pth():
    remove(PTH_PATH)
    with open(PTH_PATH, "w") as pth:
        pth.write(";".join(inspect.getsource(__pth_import_fn).splitlines()[1:]).strip())
