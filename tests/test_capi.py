import sys, pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.joinpath("src").resolve()))
import socket
from openssl_engine_capi import *
from sslcontext import PyOpenSSLContext, SSLContext
from ssl import enum_certificates, PROTOCOL_TLS
from OpenSSL import crypto
from x509creds import Certificate


def test_create_engine():
    CAPIEngine()


def test_list_certs():
    with CAPIEngine() as capi:
        certs = capi.list_certs(store="ROOT")
        assert (
            len(certs) > 0
        ), "There should be at least 1 certificate in the Trusted Root Certificate store"


def test_capi_and_ssl_certs():
    with CAPIEngine() as capi:
        capi_certs: "list[tuple(str,str)]" = []
        for store in TRUSTED_STORES:
            capi_certs += [cert.to_cryptography() for cert in capi.store_certs(store)]
        capi_certs: "set[Certificate]" = set(capi_certs)
        certs = []
        for store in TRUSTED_STORES:
            certs.extend(
                [
                    crypto.load_certificate(
                        crypto.FILETYPE_ASN1, cert
                    ).to_cryptography()
                    for cert, _, _ in enum_certificates(store)
                ]
            )
        certs: "set[Certificate]" = set(certs)
        assert len(certs) == len(
            capi_certs
        ), "There should same ammount of certs from the two methods"

        for cert in certs:

            found = next(
                (
                    True
                    for capi_cert in capi_certs
                    if capi_cert.serial_number == cert.serial_number
                ),
                False,
            )
            assert (
                found
            ), f"Certificate with subject: {cert.subject.rfc4514_string()} and sn:{cert.serial_number} not found in certs returned by capi"


#PKI_HOST = ("pki.example.lan", 9443)
PKI_HOST = ("google.com", 443)


def test_ssl_socket():
    # Simple Socker with context
    ctx = PyOpenSSLContext(PROTOCOL_TLS)
    engine = CAPIEngine()
    set_client_cert_engine(ctx.pyopenssl(), engine)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(PKI_HOST)
    s = ctx.wrap_socket(s)

    s.sendall("CONNECT %s:%s HTTP/1.0\r\nConnection: close\r\n\r\n" % PKI_HOST)

    print(s.recv(4096).decode())


def test_requests():
    import requests

    s = requests.Session()
    r = s.get("https://%s:%s" % PKI_HOST)
    print(r.text)


if __name__ == "__main__":
    test_list_certs()
    test_capi_and_ssl_certs()
    # test_ssl_socket()
    # test_requests()
