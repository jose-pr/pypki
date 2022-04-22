from cryptography.hazmat.primitives.serialization import (
    load_der_private_key as _load_der_private_key,
    Encoding as _Encoding,
    NoEncryption as _NoEncryption,
    BestAvailableEncryption as _Encryption,
    PrivateFormat as _PrivFormat,
)

from cryptography.x509 import load_der_x509_certificate as _load_der_x509_certificate
from typing import cast as _cast, Callable as _Func, Iterable as _Iter

from .._vendor.crypto import *
from .._vendor.pyopenssl import _new_mem_buf, _lib, _ffi

load_cert = _cast(_Func[[bytes], Certificate], _load_der_x509_certificate)
load_key = _cast(_Func[[bytes, "bytes|None"], PrivateKey], _load_der_private_key)


def load(data: bytes, password: bytes = None):
    try:
        yield load_key(data, password)
    except ValueError:
        yield from load_certs(data)


def load_certs(data: bytes) -> _Iter[Certificate]:
    bundle_bio = _new_mem_buf(data)
    while True:
        _x509 = _lib.d2i_X509_bio(bundle_bio, _ffi.NULL)
        if _x509 == _ffi.NULL:
            break
        cert_bio = _new_mem_buf()
        if _lib.i2d_X509_bio(cert_bio, _x509) != 1:
            raise Exception("Error converting certs to bytes")
        cert_buffer = _ffi.new("char**")
        cert_len = _lib.BIO_get_mem_data(cert_bio, cert_buffer)
        yield load_cert(_ffi.buffer(cert_buffer[0], cert_len)[:])


def dump_key(key: PrivateKey, password: "bytes|None" = None):
    return key.private_bytes(
        _Encoding.DER,
        _PrivFormat.PKCS8,
        _Encryption(password) if password else _NoEncryption(),
    )


def dump_cert(
    cert: "Certificate|None" = None,
):
    return cert.public_bytes(_Encoding.DER)


def dump(
    key: "PrivateKey|None" = None,
    cert: "Certificate|None" = None,
    chain: "_Iter[Certificate]|None" = None,
    password: "bytes|None" = None,
):
    return (
        dump_key(key, password) if key else bytes(),
        cert.public_bytes(_Encoding.DER) if cert else bytes(),
        [ca.public_bytes(_Encoding.DER) for ca in chain or []],
    )
