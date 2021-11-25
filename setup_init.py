import os
import pathlib
import shutil
from typing import Type
from setuptools import setup as _setup

root = os.path.dirname(__file__)


def remove_dir(path: str):
    if os.path.exists(path):
        shutil.rmtree(path)


def remove_file(path: str):
    if os.path.exists(path):
        os.remove(path)


def pre_setup():

    remove_dir(os.path.join(root, "build"))

    for path in os.listdir(os.path.join(root, "src")):
        if path.endswith(".egg-info"):
            remove_dir(os.path.join(root, "src", path))


def post_setup():
    arts = os.path.join(root, "artifacts")
    if not os.path.exists(arts):
        os.mkdir(arts)

    for path in os.listdir(os.path.join(root, "src")):
        if path.endswith(".egg-info"):
            src = os.path.join(root, "src", path)
            dst = os.path.join(arts, path)
            remove_dir(dst)
            shutil.move(src, dst)

        remove_dir(os.path.join(root, "build"))


def setup(*args, **kwargs):
    pre_setup()

    name: str = kwargs["name"].replace("-", "_")
    readme = (pathlib.Path(__file__).parent / "src" / name / "README.md").read_text()
    _setup(
        *args,
        long_description=readme,
        long_description_content_type="text/markdown",
        author="Jose A.",
        author_email="jose-pr@coqui.dev",
        url="https://github.com/jose-pr/pypki",
        package_dir={"": "src"},
        packages=[name],
        **kwargs
    )
    post_setup()


setup: Type[_setup] = setup
