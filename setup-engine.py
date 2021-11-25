#!/usr/bin/env python

from setup_init import *

setup(
    name="openssl-engine",
    version="1.0.1",
    description="Python openssl engine support",
    install_requires=["pyopenssl", "cryptography>=36"],
)
