import os, pathlib, sys

_file = pathlib.Path(__file__)
_root = _file.parent.parent.parent

sys.path.insert(0, str(_root.joinpath("src").resolve()))
os.environ["USER_HOME"] = str(_root.joinpath(".private").resolve())

from netproxy.__main__ import start

try:
    start()
except Exception as e:
    print(e)
input("Press any key to close")