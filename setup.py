from ast import arg
from pathlib import Path
import shutil, sys
from setuptools import setup as _setup, find_packages


root = Path(__file__).parent
PKG = sys.argv.pop(1).replace("-", "_")
PKG_NAME = PKG.replace("_", "-")

src = root / "src" / PKG
dist = root / "dist" / PKG
dist.mkdir(exist_ok=True, parents=True)


def clean_dist():
    if PKG == "_":
        for path in (root / "dist").iterdir():
            shutil.rmtree(path)
    else:
        for path in dist.iterdir():
            path.unlink()


def clean():

    for path in (root / "src").iterdir():
        if path.suffix == ".egg-info":
            shutil.rmtree(path)
    for path in root.iterdir():
        if path.suffix == ".egg-info":
            shutil.rmtree(path)
    shutil.rmtree(root / "build", ignore_errors=True)


if sys.argv[1] == "clean-dist":
    clean_dist()
    exit()


pkgs = find_packages(str(src))
readme_file = next((f for f in src.iterdir() if f.stem == "README"), None)
if readme_file:
    readme = readme_file.read_text()

    if readme_file.suffix == ".rst":
        readme_type = f"text/x-rst"
    elif readme_file.suffix == ".md":
        readme_type = "text/markdown"
    else:
        readme_type = "text/plain"
else:
    readme = None
    readme_type = None
print(readme_type)


def setup(**kwargs):
    _setup(
        name=PKG.replace("_", "-"),
        version=(src / "VERSION").read_text(),
        description=(src / "DESCRIPTION").read_text(),
        long_description=readme,
        long_description_content_type=readme_type
        if readme_type != "text/x-rst"
        else None,
        author="Jose A.",
        author_email="jose-pr@coqui.dev",
        url=f"https://github.com/jose-pr/{root.resolve().name}",
        package_dir={"": "src"},
        packages=[PKG, *[f"{PKG}.{pkg}" for pkg in pkgs]],
        install_requires=(src / "requirements.txt").read_text().splitlines(),
        **kwargs,
    )


clean()
if sys.argv[1] == "dist-build":
    sys.argv.append("--dist-dir")
    sys.argv.append(f"dist/{PKG}")
    clean_dist()
    sys.argv[1] = "bdist_wheel"
    setup()
    sys.argv[1] = "sdist"
    setup()
else:
    setup()

clean()
