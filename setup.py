from pathlib import Path
import shutil, sys
from setuptools import setup as _setup, find_packages


root = Path(__file__).parent
PKG = sys.argv.pop(1)
src = root / "src" / PKG

(root / "dist").mkdir(exist_ok=True)
if sys.argv[1] == "clean_dist":
    for path in (root / "dist").iterdir():
        path.unlink()
    exit()


def clean():
    for path in (root / "src").iterdir():
        if path.suffix == ".egg-info":
            shutil.rmtree(path)
    for path in root.iterdir():
        if path.suffix == ".egg-info":
            shutil.rmtree(path)
    shutil.rmtree(root / "build", ignore_errors=True)


pkgs = find_packages(str(src))
print(pkgs)


def setup(*args, **kwargs):
    clean()
    readme = (src / "README.md").read_text()
    _setup(
        *args,
        long_description=readme,
        long_description_content_type="text/markdown",
        author="Jose A.",
        author_email="jose-pr@coqui.dev",
        url=f"https://github.com/jose-pr/{root.resolve().name}",
        package_dir={"": "src"},
        packages=[PKG, *pkgs],
        install_requires=(src / "requirements.txt").read_text().splitlines(),
        **kwargs,
    )
    clean()


setup(
    name=PKG.replace("_", "-"),
    version=(src / "VERSION").read_text(),
    description=(src / "DESCRIPTION").read_text(),
)
