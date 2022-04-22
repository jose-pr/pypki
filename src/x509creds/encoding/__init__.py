from enum import IntEnum as _IntEnum
from typing_extensions import TypeAlias as _Alias
from typing import Callable as _Func, BinaryIO as _BinIO, Iterable as _Iter
from cryptography.hazmat.primitives.serialization import (
    Encoding as _Encoding,
)

from . import pem, der, pkcs12
from ._decoders import (
    Encoded,
    EncodedIO, 
    _ENCODING_SUFFIX_MAP,
)
from .._vendor.crypto import *

PasswordLike: _Alias = "bytes | str | None | _Func[[], str| bytes]"


def _getPassword(password: PasswordLike) -> "bytes|None":
    if callable(password):
        password = password()
    return password.encode() if isinstance(password, str) else password


class Encoding(_IntEnum):
    PKCS12 = 0
    PEM = 1
    DER = 2

    def exts(self):
        if self is Encoding.PKCS12:
            return ["p12", "pfx", "pkcs12"]
        elif self is Encoding.PEM:
            return ["pem", "crt", "key"]
        elif self is Encoding.DER:
            return ["der", "cer", "asn1"]
        else:
            raise ValueError(self)


for t in Encoding:
    for e in t.exts():
        _ENCODING_SUFFIX_MAP["." + e] = t


def load_cert(data: bytes, encoding: Encoding, password: PasswordLike = None):
    if encoding is Encoding.PKCS12:
        cert = pkcs12.load_cert(data, _getPassword(password))
        if cert is None:
            raise ValueError("No certificate found")
        return cert
    elif encoding is Encoding.PEM:
        return pem.load_cert(data)
    elif encoding is Encoding.DER:
        return der.load_cert(data)
    else:
        raise ValueError(f"Invalid encoding {encoding}")


def load_key(data: bytes, encoding: Encoding, password: PasswordLike = None):
    password = _getPassword(password)
    if encoding is Encoding.PKCS12:
        key = pkcs12.load_key(data, password)
        if key is None:
            raise ValueError("No private key found")
        return key
    elif encoding is Encoding.PEM:
        return pem.load_key(data, password)
    elif encoding is Encoding.DER:
        return der.load_key(data, password)
    else:
        raise ValueError(f"{encoding} is not a valid encoding")


def dump_cert(cert: Certificate, encoding: Encoding):
    if encoding is Encoding.DER:
        return cert.public_bytes(_Encoding.DER)
    elif encoding is Encoding.PEM:
        return cert.public_bytes(_Encoding.PEM)
    elif encoding is Encoding.PKCS12:
        return pkcs12.dump(cert=cert)
    else:
        raise ValueError(f"Invalid encoding {encoding}")


def dump_key(key: PrivateKey, encoding: Encoding, password: PasswordLike = None):
    password = _getPassword(password)
    if encoding is Encoding.DER:
        return der.dump_key(key, password)
    elif encoding is Encoding.PEM:
        return pem.dump_key(key, password)
    elif encoding is Encoding.PKCS12:
        return pkcs12.dump(key=key, password=password)
    else:
        raise ValueError(f"Invalid encoding {encoding}")


def load_certs(
    data: "bytes|_BinIO", encoding: Encoding, password: PasswordLike = None
) -> "list[Certificate]":
    password = _getPassword(password)
    if encoding is Encoding.PKCS12:
        store = pkcs12.load_creds(
            data.read() if not isinstance(data, bytes) else data, password
        )
        return [store[1], *store[2]]
    elif encoding is Encoding.PEM:
        return list(pem.load_certs(data))
    elif encoding is Encoding.DER:
        return list(
            der.load_certs(data.read() if not isinstance(data, bytes) else data)
        )
    else:
        raise ValueError(f"Invalid encoding {encoding}")


def load(
    io: "_BinIO|bytes", encoding: Encoding, password: PasswordLike = None
) -> "_Iter[PrivateKey|Certificate]":
    password = _getPassword(password)
    if encoding is Encoding.PKCS12:
        yield from pkcs12.load(io.read() if not isinstance(io, bytes) else io, password)
    elif encoding is Encoding.PEM:
        yield from pem.load(io, password)
    elif encoding is Encoding.DER:
        yield from der.load(io.read() if not isinstance(io, bytes) else io, password)
    else:
        raise ValueError(f"Invalid encoding {encoding}")


class X509EncodedStore:
    __slots__ = ('io',)
    
    def __init__(self, encoded: Encoded):
        self.io = EncodedIO(encoded)


    @property
    def encoding(self) -> bytes:
        self.io.encoding

    @property
    def password(self) -> PasswordLike:
        self.io.password
   
    def __iter__(self):
        with self.io as io:
            yield from load(io, self.encoding, self.password)
