from typing import Tuple, cast
from functools import reduce
from pathlib import Path
from typing import List, NamedTuple
from cryptography.hazmat.primitives.serialization import (
    pkcs12,
    load_pem_private_key,
    load_der_private_key,
    Encoding as CryptEncoding,
    PrivateFormat,
    BestAvailableEncryption,
    NoEncryption,
)
from cryptography.hazmat.primitives.asymmetric.types import (
    PRIVATE_KEY_TYPES as PrivateKey,
    PUBLIC_KEY_TYPES as PublicKey,
)
from cryptography import x509
from cryptography.x509 import Certificate
from enum import IntEnum
import re


class Encoding(IntEnum):
    PKCS12 = 0
    PEM = 1
    DER = 2

    def exts(self):
        if self is Encoding.PKCS12:
            return ["p12", "pfx", "pkcs12"]
        elif self is Encoding.PEM:
            return ["pem", "key", "crt"]
        elif self is Encoding.DER:
            return ["cer", "der", "asn1"]
        else:
            raise ValueError(self)

    @staticmethod
    def from_suffix(ext: str):
        if not ext.startswith("."):
            ext = "." + ext
        return _ENCODING_SUFFIX_MAP[ext]


_ENCODING_SUFFIX_MAP: "dict[str,Encoding]" = {}
for t in Encoding:
    for e in t.exts():
        _ENCODING_SUFFIX_MAP["." + e] = t


def get_path_and_encoding(encoded: "str|tuple[str, str|Encoding]"):
    if isinstance(encoded, str):
        encoding: Encoding = None
    else:
        encoded, encoding = encoded
    path = Path(encoded)
    if not encoding:
        encoding = Encoding.from_suffix(path.suffix)
    elif isinstance(encoding, str):
        encoding = Encoding[encoding]
    return path, encoding


def get_bytes_and_encoding(encoded: "str|tuple[str, str|Encoding]"):
    path, encoding = get_path_and_encoding(encoded)
    return path.read_bytes(), encoding


def load_cert(data: bytes, encoding: Encoding, password: str = None):
    password = password.encode() if password else None
    if encoding is Encoding.PKCS12:
        store = pkcs12.load_pkcs12(data, password)
        return store.cert.certificate
    elif encoding is Encoding.PEM:
        return x509.load_pem_x509_certificate(data)
    elif encoding is Encoding.DER:
        return x509.load_der_x509_certificate(data)
    else:
        raise ValueError(f"Invalid encoding {encoding}")


def load_key(data: bytes, encoding: Encoding, password: str = None):
    password = password.encode() if password else None
    if encoding is Encoding.PKCS12:
        store = pkcs12.load_pkcs12(data, password)
        if store.key is None:
            raise ValueError("Data doesnt include a key")
        return store.key
    elif encoding is Encoding.PEM:
        return load_pem_private_key(data, password)
    elif encoding is Encoding.DER:
        return load_der_private_key(data, password)
    else:
        raise ValueError(f"Invalid encoding {encoding}")


def dump_cert(cert: Certificate, encoding: Encoding):
    if encoding is Encoding.DER:
        return cert.public_bytes(CryptEncoding.DER)
    elif encoding is Encoding.PEM:
        return cert.public_bytes(CryptEncoding.PEM)
    elif encoding is Encoding.PKCS12:
        return pkcs12.serialize_key_and_certificates(
            cert.subject.rfc4514_string(),
            None,
            None,
            None,
            NoEncryption(),
        )
    else:
        raise ValueError(f"Invalid encoding {encoding}")


def dump_key(key: PrivateKey, encoding: Encoding, password: str = None):
    encryption = (
        NoEncryption()
        if password is None
        else BestAvailableEncryption(password.encode())
    )
    if encoding is Encoding.DER:
        return key.private_bytes(CryptEncoding.DER, PrivateFormat.PKCS8, encryption)
    elif encoding is Encoding.PEM:
        return key.private_bytes(CryptEncoding.PEM, PrivateFormat.PKCS8, encryption)
    elif encoding is Encoding.PKCS12:
        return pkcs12.serialize_key_and_certificates(
            "PRIVATE KEY",
            key,
            None,
            None,
            encryption,
        )
    else:
        raise ValueError(f"Invalid encoding {encoding}")


_PEM_SECTION = re.compile(rb"-----([^- ]+) ([^-]+)-----")


def parse_pem(pem: bytes):
    result: "list[tuple[str, bytes]]" = []
    sectionName = None
    sectionData = bytes()
    for line in pem.splitlines():
        line = line.strip()
        match = _PEM_SECTION.match(line)
        if match:
            sectionData += b"\n" + line
            if sectionName is not None:
                expecting = b"-----END " + sectionName + b"-----"
                if expecting != match[0]:
                    raise ValueError(f"Expecting: {expecting} Found:{match[0]}")
                result.append((sectionName.decode(), sectionData))
                sectionName = None
                sectionData = bytes()
            else:
                if match[1] != b"BEGIN":
                    raise ValueError(f"Expecting: BEGIN Found:{match[0]}")
                sectionName = match[2]
        elif sectionName:
            sectionData += b"\n" + line
    return result


def load_certs(
    data: bytes, encoding: Encoding, password: str = None
) -> "list[Certificate]":
    password = password.encode() if password else None
    if encoding is Encoding.PKCS12:
        store = pkcs12.load_pkcs12(data, password)
        return [store.cert.certificate] + store.additional_certs
    elif encoding is Encoding.PEM:
        certs = []
        for section, data in parse_pem(data):
            if section == "CERTIFICATE":
                certs.append(x509.load_pem_x509_certificate(data))
        return certs
    elif encoding is Encoding.DER:
        return [x509.load_der_x509_certificate(data)]
    else:
        raise ValueError(f"Invalid encoding {encoding}")


def load_store(
    data: bytes, encoding: Encoding, password: str = None
) -> "tuple[Certificate, PrivateKey|None, list[Certificate]]":
    password = password.encode() if password else None
    if encoding is Encoding.PKCS12:
        store = pkcs12.load_pkcs12(data, password)
        return store.cert.certificate, store.key, store.additional_certs
    elif encoding is Encoding.PEM:
        key = None
        certs = []
        for section, data in parse_pem(data):
            if section == "CERTIFICATE":
                certs.append(x509.load_pem_x509_certificate(data))
            elif "PRIVATE KEY" in section and key is None:
                key = load_pem_private_key(data, password)
        return certs[0], key, certs[1:]
    elif encoding is Encoding.DER:
        return x509.load_der_x509_certificate(data), None, None
    else:
        raise ValueError(f"Invalid encoding {encoding}")


Encoded = Tuple[bytes, Encoding]


class X509Credentials(NamedTuple):
    cert: Certificate
    key: PrivateKey

    def dump(self, encoding: Encoding, password: str = None):
        encryption = (
            NoEncryption()
            if password is None
            else BestAvailableEncryption(password.encode())
        )
        if encoding is Encoding.DER:
            return self.cert.public_bytes(CryptEncoding.DER), self.key.private_bytes(
                CryptEncoding.DER, PrivateFormat.PKCS8, encryption
            )
        elif encoding is Encoding.PEM:
            return self.cert.public_bytes(CryptEncoding.PEM) + self.key.private_bytes(
                CryptEncoding.PEM, PrivateFormat.PKCS8, encryption
            )
        elif encoding is Encoding.PKCS12:
            return pkcs12.serialize_key_and_certificates(
                self.cert.subject.rfc4514_string(),
                self.key,
                self.cert,
                None,
                encryption,
            )
        else:
            raise ValueError(f"Invalid encoding {encoding}")

    def load(self, cert: Encoded, key: Encoded, password: str = None):
        cert, _key, _chain = load_store(*cert, password)
        if key is None:
            key = _key
            if _key is None:
                raise ValueError("Key not provided")
        else:
            key = load_key(*key, password)
        return X509Credentials(cert, key)


class X509FullCredentials(NamedTuple):
    cert: Certificate
    key: PrivateKey
    chain: "list[Certificate]"

    def dump(self, encoding: Encoding, password: str = None):
        encryption = (
            NoEncryption()
            if password is None
            else BestAvailableEncryption(password.encode())
        )
        if encoding is Encoding.DER:
            return (
                self.cert.public_bytes(CryptEncoding.DER),
                self.key.private_bytes(
                    CryptEncoding.DER, PrivateFormat.PKCS8, encryption
                ),
                reduce(
                    lambda acc, cert: acc.append(cert.public_bytes(CryptEncoding.DER)),
                    self.chain,
                    [],
                )
                or cast(List[bytes], []),
            )
        elif encoding is Encoding.PEM:
            return self.key.private_bytes(
                CryptEncoding.PEM, PrivateFormat.PKCS8, encryption
            ) + reduce(
                lambda acc, cert: acc + cert.public_bytes(CryptEncoding.PEM),
                self.chain,
                self.cert.public_bytes(CryptEncoding.PEM),
            )
        elif encoding is Encoding.PKCS12:
            return pkcs12.serialize_key_and_certificates(
                self.cert.subject.rfc4514_string(),
                self.key,
                self.cert,
                self.chain,
                encryption,
            )
        else:
            raise ValueError(f"Invalid encoding {encoding}")

    def load(
        self, cert: Encoded, key: Encoded, chain: "list[Encoded]", password: str = None
    ):
        cert, _key, _chain = load_store(*cert, password)
        if key is None:
            key = _key
            if _key is None:
                raise ValueError("Key not provided")
        else:
            key = load_key(*key, password)

        if chain:
            for data, encoding in chain:
                _chain += load_certs(data, encoding, password)

        return X509FullCredentials(cert, key, _chain)
