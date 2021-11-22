import socket
import ssl
from openssl_engine_capi import *
from openssl_engine_capi.utils import (
    WindowsSSLContext,
    get_capi_store_certs,
    trusted_certs,
    TRUSTED_STORES,
    inject,
)


def test_create_engine():
    CAPIEngine()


def test_list_certs():
    with CAPIEngine() as capi:
        certs = capi.list_certs(store="ROOT")
        assert (
            len(certs) > 0
        ), "There should be at least 1 certificate in the Trusted Root Certificate store"


def test_trusted_certs():
    certs = trusted_certs()
    assert (
        len(certs) > 0
    ), "There should be at least 1 certificate in the Trusted Root Certificate store"


def test_capi_and_ssl_certs():
    with CAPIEngine() as capi:
        capi_certs = []
        for store in TRUSTED_STORES:
            capi_certs += [
                (str(cert.get_subject()), str(cert.get_serial_number()))
                for cert in set(get_capi_store_certs(store))
            ]
        capi_certs = list(set(capi_certs))
        certs = [
            (str(cert.get_subject()), str(cert.get_serial_number()))
            for cert in trusted_certs(TRUSTED_STORES, filter=lambda a, b: True)
        ]
        certs = list(set(certs))
        assert len(certs) == len(
            capi_certs
        ), "There should same ammount of certs from the two methods"


PKI_HOST = ("pki.example.lan", 9443)


def test_ssl_socket():
    # Simple Socker with context
    ctx = WindowsSSLContext()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(PKI_HOST)
    s = ctx.wrap_socket(s)

    s.sendall("CONNECT %s:%s HTTP/1.0\r\nConnection: close\r\n\r\n" % PKI_HOST)

    print(s.recv(4096).decode())


def test_requests():
    inject()
    import requests
    s = requests.Session()
    r = s.get("https://%s:%s" % PKI_HOST)
    print(r.text)


if __name__ == "__main__":
    test_list_certs()
    test_capi_and_ssl_certs()
    test_ssl_socket()
   # test_requests()
