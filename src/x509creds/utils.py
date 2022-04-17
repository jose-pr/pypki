import re as _re
from datetime import datetime, timedelta
from enum import IntEnum as _IntEnum
from enum import IntFlag as _IntFlag
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Literal, NamedTuple, Tuple, overload, Union

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    PRIVATE_KEY_TYPES as PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.types import (
    PUBLIC_KEY_TYPES as PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption as _TextEncryption,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding as _Encoding,
    KeySerializationEncryption as _Encryption,
)
from cryptography.hazmat.primitives.serialization import NoEncryption as _NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat as _PrivateFormat
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key as _load_der_private_key,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key as _load_pem_private_key,
)
from cryptography.hazmat.primitives.serialization import pkcs12 as _pkcs12
from cryptography.x509 import Certificate, CertificateBuilder
from cryptography.x509.oid import ExtendedKeyUsageOID
from typing_extensions import TypeGuard as _TypeGuard
from os import PathLike as _PathLike

if TYPE_CHECKING:
    from OpenSSL import crypto as _crypto
else:
    try:
        from OpenSSL import crypto as _crypto
    except ImportError:
        _crypto = None

ExtensionLike = Union[
    x509.Extension,
    Tuple[x509.ExtensionType, bool],
    Tuple[x509.ObjectIdentifier, x509.ExtensionType, bool],
]
KeyUsage = Literal[
    "key_cert_sign",
    "crl_sign",
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "encipher_only",
    "decipher_only",
]


DEF_HASH_ALG = _SHA256()


class CertPurpose(_IntFlag):
    _ = 0
    CA = 1
    CLIENT = 2
    SERVER = 3


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

    @staticmethod
    def from_suffix(ext: str):
        if not ext.startswith("."):
            ext = "." + ext
        return _ENCODING_SUFFIX_MAP[ext]


PathLike = Union[str, _PathLike]
PasswordLike = Union[bytes, str, None]

ProtectedByteEncoded = Tuple[bytes, Encoding, PasswordLike]
EncodedBytes = Union[Tuple[bytes, Encoding], ProtectedByteEncoded]
ProtectedEncodedFile = Union[
    Tuple[PathLike, Encoding, PasswordLike], Tuple[PathLike, PasswordLike]
]
EncodedFile = Union[Tuple[PathLike, Encoding], PathLike, ProtectedEncodedFile]
Encoded = Union[EncodedFile, EncodedBytes]


def _getEncryption(password: PasswordLike) -> _Encryption:
    if isinstance(password, _Encryption):
        return password
    elif isinstance(password, str):
        return _TextEncryption(password.encode())
    elif password is None:
        return _NoEncryption()
    else:
        return _TextEncryption(password)


def _as_bytes(val, encoding: str = "utf-8") -> bytes:
    return val.encode(encoding) if isinstance(val, str) else val


class _ByteDecoder(NamedTuple):
    data: bytes
    encoding: Encoding
    encryption: PasswordLike

    @staticmethod
    def new(encoded: EncodedBytes):
        if len(encoded) == 2:
            data, encoding = encoded
            encoding = None
        else:
            data, encoding, encryption = encoded
        return _ByteDecoder(data, encoding, encryption)


class _FileDecoder(NamedTuple):
    path: Path
    encoding: Encoding
    encryption: PasswordLike

    @staticmethod
    def new(encoded: EncodedFile):
        if not isinstance(encoded, tuple):
            path = encoded
            encoding = None
            encryption = None
        elif len(encoded) == 2:
            path, encoding_or_password = encoded
            if isinstance(encoding_or_password, int):
                encoding = encoding_or_password
                encryption = None
            else:
                encryption = encoding_or_password
                encoding = None
        else:
            path, encoding, encryption = encoded

        path = Path(path)
        if not encoding:
            encoding = Encoding.from_suffix(path.suffix)
        elif isinstance(encoding, str):
            encoding = Encoding[encoding]

        return _FileDecoder(path, encoding, encryption)

    def to_bytedecoder(self):
        return _ByteDecoder(self.path.read_bytes(), self.encoding, self.encryption)


_ENCODING_SUFFIX_MAP: "dict[str,Encoding]" = {}
for t in Encoding:
    for e in t.exts():
        _ENCODING_SUFFIX_MAP["." + e] = t


class _X509Creds(NamedTuple):
    cert: Certificate
    key: PrivateKey
    chain: "list[Certificate]"


class _X509PubCreds(NamedTuple):
    cert: Certificate
    chain: "list[Certificate]"


def load_cert(data: bytes, encoding: Encoding, password: PasswordLike = None):
    password = _as_bytes(password)
    if encoding is Encoding.PKCS12:
        store = _pkcs12.load_pkcs12(data, password)
        return store.cert.certificate
    elif encoding is Encoding.PEM:
        return x509.load_pem_x509_certificate(data)
    elif encoding is Encoding.DER:
        return x509.load_der_x509_certificate(data)
    else:
        raise ValueError(f"Invalid encoding {encoding}")


def load_key(data: bytes, encoding: Encoding, password: PasswordLike = None):
    password = _as_bytes(password)
    if encoding is Encoding.PKCS12:
        store = _pkcs12.load_pkcs12(data, password)
        if store.key is None:
            raise ValueError("Data doesnt include a key")
        return store.key
    elif encoding is Encoding.PEM:
        return _load_pem_private_key(data, password)
    elif encoding is Encoding.DER:
        return _load_der_private_key(data, password)
    else:
        raise ValueError(f"Invalid encoding {encoding}")


def dump_cert(cert: Certificate, encoding: Encoding):
    if encoding is Encoding.DER:
        return cert.public_bytes(_Encoding.DER)
    elif encoding is Encoding.PEM:
        return cert.public_bytes(_Encoding.PEM)
    elif encoding is Encoding.PKCS12:
        return _pkcs12.serialize_key_and_certificates(
            cert.subject.rfc4514_string(),
            None,
            None,
            None,
            _NoEncryption(),
        )
    else:
        raise ValueError(f"Invalid encoding {encoding}")


def dump_key(key: PrivateKey, encoding: Encoding, password: PasswordLike = None):
    encryption = _getEncryption(password)
    if encoding is Encoding.DER:
        return key.private_bytes(_Encoding.DER, _PrivateFormat.PKCS8, encryption)
    elif encoding is Encoding.PEM:
        return key.private_bytes(_Encoding.PEM, _PrivateFormat.PKCS8, encryption)
    elif encoding is Encoding.PKCS12:
        return _pkcs12.serialize_key_and_certificates(
            "PRIVATE KEY",
            key,
            None,
            None,
            encryption,
        )
    else:
        raise ValueError(f"Invalid encoding {encoding}")


_PEM_SECTION = _re.compile(rb"-----([^- ]+) ([^-]+)-----")


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
    data: bytes, encoding: Encoding, password: PasswordLike = None
) -> "list[Certificate]":
    password = _as_bytes(password)
    if encoding is Encoding.PKCS12:
        store = _pkcs12.load_pkcs12(data, password)
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


def load_encoded_store(encoded: Encoded):
    if not isinstance(encoded, tuple) or not isinstance(encoded[0], bytes):
        store = _FileDecoder.new(encoded).to_bytedecoder()
    else:
        store = _ByteDecoder.new(encoded)

    return load_store(*store)


def load_store(
    data: bytes, encoding: Encoding, password: PasswordLike = None
) -> "tuple[Certificate, PrivateKey|None, list[Certificate]]":
    password = _as_bytes(password)
    if encoding is Encoding.PKCS12:
        store = _pkcs12.load_pkcs12(data, password)
        return store.cert.certificate, store.key, store.additional_certs
    elif encoding is Encoding.PEM:
        key = None
        certs = []
        for section, data in parse_pem(data):
            if section == "CERTIFICATE":
                certs.append(x509.load_pem_x509_certificate(data))
            elif "PRIVATE KEY" in section and key is None:
                key = _load_pem_private_key(data, password)
        return certs[0], key, certs[1:]
    elif encoding is Encoding.DER:
        try:
            return x509.load_der_x509_certificate(data), None, []
        except ValueError:
            return None, _load_der_private_key(data, password), []
    else:
        raise ValueError(f"Invalid encoding {encoding}")


def is_public_key(key: "PrivateKey|PublicKey") -> _TypeGuard[PublicKey]:
    return hasattr(key, "public_bytes")


DEF_KEY_SIZE = 2048
DEF_PUBLIC_EXPONENT = 65537
CERT_MAX_AGE = timedelta(seconds=397 * 24 * 60 * 60)


def parse_extension(ext_like: ExtensionLike) -> x509.Extension:
    if isinstance(ext_like, x509.Extension):
        return ext_like
    elif isinstance(ext_like, x509.ExtensionType):
        return x509.Extension(oid=ext_like.oid, value=ext_like, critical=False)
    elif len(ext_like) == 2:
        return x509.Extension(oid=ext_like[0].oid, value=ext_like, critical=ext_like[1])
    else:
        return x509.Extension(oid=ext_like[0], value=ext_like[1], critical=ext_like[2])


@overload
def cert_builder(
    subject: "x509.Name|str",
    key: "int|None" = None,
    purpose: CertPurpose = None,
    not_before: "datetime|int|timedelta" = None,
    not_after: "datetime|int|timedelta" = None,
    extensions: Iterable[ExtensionLike] = None,
    key_usage: "dict[KeyUsage,bool]" = None,
    ext_key_usage: "list" = None,
) -> "tuple[CertificateBuilder, PrivateKey]":
    ...


@overload
def cert_builder(
    subject: "x509.Name|str",
    key: "PrivateKey|PublicKey" = None,
    purpose: CertPurpose = None,
    not_before: "datetime|int|timedelta" = None,
    not_after: "datetime|int|timedelta" = None,
    extensions: Iterable[ExtensionLike] = None,
    key_usage: "dict[KeyUsage,bool]" = None,
    ext_key_usage: "list" = None,
) -> "CertificateBuilder":
    ...


def cert_builder(
    subject: "x509.Name|str",
    key: "PrivateKey|PublicKey|int|None" = None,
    purpose: CertPurpose = None,
    not_before: "datetime|int|timedelta" = None,
    not_after: "datetime|int|timedelta" = None,
    extensions: Iterable[ExtensionLike] = None,
    key_usage: "dict[KeyUsage,bool]" = None,
    ext_key_usage: "list" = None,
):
    key = key or DEF_KEY_SIZE
    extensions = [parse_extension(e) for e in extensions] if extensions else []

    if isinstance(key, int):
        _ret_key = True
        key: PrivateKey = _rsa.generate_private_key(DEF_PUBLIC_EXPONENT, key)
    else:
        _ret_key = False

    if is_public_key(key):
        public_key = key
    else:
        public_key = key.public_key()

    subject = (
        subject
        if isinstance(subject, x509.Name)
        else x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)])
    )

    now = datetime.now()
    if not_before is None:
        if not_after is None or isinstance(not_after, (int, timedelta)):
            not_before = now
        else:
            not_before = not_after - CERT_MAX_AGE
    elif isinstance(not_before, int):
        not_before = now + timedelta(not_before)
    elif isinstance(not_before, timedelta):
        not_before = now + not_before

    if not_after is None:
        not_after = not_before + CERT_MAX_AGE
    elif isinstance(not_after, int):
        not_after = not_before + timedelta(not_after)
    elif isinstance(not_after, timedelta):
        not_after = not_before + not_after

    builder = CertificateBuilder(
        subject_name=subject,
        serial_number=x509.random_serial_number(),
        public_key=public_key,
        not_valid_before=not_before,
        not_valid_after=not_after,
        extensions=extensions or [],
    )
    key_usage: "dict[KeyUsage,bool]" = key_usage or {}
    ext_key_usage = ext_key_usage or []

    if CertPurpose.CA in purpose:
        key_usage = {"key_cert_sign": True, "crl_sign": True}
        builder = builder.add_extension(x509.BasicConstraints(True, 0), critical=True)

    if CertPurpose.SERVER in purpose:
        key_usage["digital_signature"] = True
        key_usage["key_agreement"] = True
        key_usage["key_encipherment"] = True
        ext_key_usage.append(ExtendedKeyUsageOID.SERVER_AUTH)

    if CertPurpose.CLIENT in purpose:
        key_usage["key_agreement"] = True
        key_usage["key_encipherment"] = True
        ext_key_usage.append(ExtendedKeyUsageOID.CLIENT_AUTH)

    if key_usage:
        for _key in KeyUsage.__args__:
            if _key not in key_usage:
                key_usage[_key] = False
        builder = builder.add_extension(
            x509.KeyUsage(**key_usage),
            critical=True,
        )
    if ext_key_usage:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(ext_key_usage), critical=False
        )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
    )
    if _ret_key:
        return builder, key
    else:
        return builder


def generate_certificate(
    builder: CertificateBuilder,
    issuer: "_X509Creds|tuple[x509.Name|Certificate, PrivateKey]",
    hash_alg: HashAlgorithm = None,
):
    signing_key = issuer[1]
    pub_key = signing_key.public_key()
    if isinstance(issuer[0], x509.Name):
        issuer_name = issuer[0]
    else:
        issuer_name = issuer[0].subject
    return (
        builder.issuer_name(issuer_name)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(pub_key),
            critical=False,
        )
        .sign(signing_key, hash_alg or DEF_HASH_ALG)
    )
