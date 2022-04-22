import sys, pathlib

import pytest
sys.path.insert(0,str(pathlib.Path(__file__).parent.parent.joinpath("src").resolve()))

from OpenSSL import SSL
from OpenSSL.SSL import Context as SSLContext, TLS_CLIENT_METHOD
from openssl_engine import *

ctx = SSLContext(SSL.SSLv23_METHOD)

def test_load_dynamic():
    SSLEngine.load_dynamic("capi", path=r"C:\Program Files\OpenSSL-Win64\bin\capi.dll")

def test_load_by_id():
    SSLEngine.load_by_id("capi")

def test_set_client_cert():
    ctx = SSLContext(TLS_CLIENT_METHOD)
    with SSLEngine.load_by_id("capi") as capi:
        set_client_cert_engine(ctx, capi)


if __name__ == "__main__":
    test_load_dynamic()
