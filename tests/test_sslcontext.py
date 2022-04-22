import sys, pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.joinpath("src").resolve()))
from sslcontext import PyOpenSSLContext, PROTOCOL_TLS

import urllib3

ctx = PyOpenSSLContext(PROTOCOL_TLS)
ctx.load_default_certs()

http = urllib3.PoolManager(ssl_context = ctx)
http.connection_pool_kw
response = http.request("GET", "https://www.google.com")
pass
