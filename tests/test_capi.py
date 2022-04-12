import socket
from typing import Callable
from openssl_engine_capi import *
import ssl

def get_windows_store_certs(storename: str):
    return [
        (crypto.load_certificate(crypto.FILETYPE_ASN1, cert), trust)
        for cert, encoding, trust in ssl.enum_certificates(storename)
    ]


def trusted_certs(
    stores: 'list[str] | None' = None,
    filter: Callable[[crypto.X509, bool], bool] = lambda cert, trusted: trusted,
):
    certs:'list[crypto.X509]' = []
    for store in stores if stores is not None else TRUSTED_STORES:
        for cert, trusted in get_windows_store_certs(store):
            if filter(cert, trusted):
                certs.append(cert)
    return certs

def test_create_engine():
    CAPIEngine()


def test_list_certs():
    with CAPIEngine() as capi:
        certs = capi.list_certs(store="ROOT")
        assert (
            len(certs) > 0
        ), "There should be at least 1 certificate in the Trusted Root Certificate store"


def test_trusted_certs():
    certs =  trusted_certs()
    assert (
        len(certs) > 0
    ), "There should be at least 1 certificate in the Trusted Root Certificate store"


def test_capi_and_ssl_certs():
    with CAPIEngine() as capi:
        capi_certs:'list[tuple(str,str)]' = []
        for store in TRUSTED_STORES:
            capi_certs += [
                (str(cert.get_subject()), str(cert.get_serial_number()))
                for cert in set(capi.store_certs(store))
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

        for subject, sn in certs:
            found = next((True for _s, _sn in capi_certs if sn == _sn), False)
            assert found, f"Certificate with subject: {subject} and sn:{sn} not found in certs returned by capi"
            


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
    import requests
    s = requests.Session()
    r = s.get("https://%s:%s" % PKI_HOST)
    print(r.text)


if __name__ == "__main__":
    test_list_certs()
    test_capi_and_ssl_certs()
    #test_ssl_socket()
    #test_requests()
