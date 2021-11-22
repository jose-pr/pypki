import os
import shutil

root = os.path.dirname(__file__)


def remove(path: str):
    if os.path.exists(path):
        shutil.rmtree(path)

remove(os.path.join(root, "build"))

for path in os.listdir(os.path.join(root, "src")):
    if path.endswith(".egg-info"):
        remove(os.path.join(root, "src", path))

