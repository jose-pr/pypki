
import socket
import requests
import pytest

from OpenSSL import SSL
from OpenSSL.SSL import Context as SSLContext
from openssl_engine import *

ctx = SSLContext(SSL.SSLv23_METHOD)

def test_load_dynamic():
    SSLEngine.load_dynamic("capi")

def test_load_by_id():
    SSLEngine.load_by_id("capi")

if __name__ == "__main__":
    test_load_dynamic()
