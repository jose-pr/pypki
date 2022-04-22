import re as _re
from cryptography.hazmat.primitives.serialization import (
    pkcs12 as _pkcs12,
    NoEncryption as _NoEncryption,
    BestAvailableEncryption as _Encryption,
)

from typing import cast as _cast, Callable as _Func, Iterable as _Iter

from .._vendor.crypto import *

load_creds = _cast(
    _Func[
        [bytes, "bytes|None"],
        "tuple[PrivateKey|None, Certificate|None, list[Certificate]]",
    ],
    _pkcs12.load_key_and_certificates,
)


def load(data: bytes, password: "bytes|None" = None) -> _Iter["Certificate|PrivateKey"]:
    key, cert, chain = load_creds(data, password)
    if cert:
        yield cert
    if key:
        yield key
    yield from chain


def load_cert(data: bytes, password: "bytes|None" = None):
    return load_creds(data, password)[1]


def load_key(data: bytes, password: "bytes|None" = None):
    return load_creds(data, password)[0]


def dump(
    key: "PrivateKey|None" = None,
    cert: "Certificate|None" = None,
    chain: "_Iter[Certificate]|None" = None,
    password: "bytes|None" = None,
):
    return _pkcs12.serialize_key_and_certificates(
        None, key, cert, chain, _Encryption(password) if password else _NoEncryption()
    )
