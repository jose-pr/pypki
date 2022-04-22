import re as _re
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key as _load_pem_private_key,
    Encoding as _Encoding,
    NoEncryption as _NoEncryption,
    BestAvailableEncryption as _Encryption,
    PrivateFormat as _PrivFormat,
)

from cryptography.x509 import load_pem_x509_certificate as _load_pem_x509_certificate
from typing import (
    cast as _cast,
    Callable as _Func,
    Iterable as _Iter,
    BinaryIO as _BinIO,
)
from io import BytesIO as _BytesIO

from .._vendor.crypto import *


load_cert = _cast(_Func[[bytes], Certificate], _load_pem_x509_certificate)
load_key = _cast(_Func[[bytes, "bytes|None"], PrivateKey], _load_pem_private_key)

_PEM_SECTION = _re.compile(rb"-----([^- ]+) ([^-]+)-----")


def tokenize(data: _BinIO) -> _Iter["tuple[str, bytes]"]:
    sectionName = None
    sectionData = bytes()
    while True:
        line = data.readline()
        if not line:
            break
        line = line.strip()
        match = _PEM_SECTION.match(line)
        sectionData += b"\n" + line
        if match:
            if sectionName is not None:
                expecting = b"-----END " + sectionName + b"-----"
                if expecting != match[0]:
                    raise ValueError(f"Expecting: {expecting} Found:{match[0]}")
                yield sectionName.decode(), sectionData
                sectionName = None
                sectionData = bytes()
            else:
                if match[1] != b"BEGIN":
                    raise ValueError(f"Expecting: BEGIN Found:{match[0]}")
                sectionName = match[2]


def load(
    data: "_BinIO|bytes", password: "bytes|None" = None
) -> _Iter["Certificate|PrivateKey"]:
    for section, data in tokenize(_BytesIO(data) if isinstance(data, bytes) else data):
        if section == "CERTIFICATE" or section == "X509 CERTIFICATE":
            yield load_cert(data)
        elif "PRIVATE KEY" in section:
            yield load_key(data, password)


def load_certs(data: "_BinIO|bytes") -> _Iter[Certificate]:
    for section, data in tokenize(_BytesIO(data) if isinstance(data, bytes) else data):
        if section == "CERTIFICATE" or section == "X509 CERTIFICATE":
            yield load_cert(data)


def dump_key(key: PrivateKey, password: "bytes|None" = None):
    return key.private_bytes(
        _Encoding.PEM,
        _PrivFormat.PKCS8,
        _Encryption(password) if password else _NoEncryption(),
    )


def dump_cert(
    cert: "Certificate|None" = None,
):
    return cert.public_bytes(_Encoding.PEM)


def dump(
    key: "PrivateKey|None" = None,
    cert: "Certificate|None" = None,
    chain: "_Iter[Certificate]|None" = None,
    password: "bytes|None" = None,
):
    data = bytearray()
    if key:
        data.extend(dump_key(key, password))
    if cert:
        data.extend(cert.public_bytes(_Encoding.PEM))
    if chain:
        for ca in chain:
            data.extend(ca.public_bytes(_Encoding.PEM))
    return bytes(data)
