#!/usr/bin/env python

from setup_init import *

setup(
    name="openssl_engine",
    version="1.0",
    description="Python openssl engine support",
    author="Jose A.",
    author_email="jose-pr@coqui.dev",
    url="https://github.com/jose-pr/pypki",
    package_dir={"": "src"},
    packages=["openssl_engine"],
    install_requires=["pyopenssl", "cryptography>=36"],
)
