from abc import ABC, abstractmethod, abstractproperty, abstractstaticmethod
from inspect import isfunction
from io import BytesIO as _BytesIO
import re as _re
from datetime import datetime, timedelta
from enum import IntEnum as _IntEnum
from enum import IntFlag as _IntFlag
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    BinaryIO,
    Callable,
    Iterable,
    Iterator,
    Literal,
    NamedTuple,
    Tuple,
    overload,
    Union,
)
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
from os import PathLike
import tarfile as _tar

if TYPE_CHECKING:
    from OpenSSL import crypto as _crypto, SSL as _SSL, _lib, _ffi, _new_mem_buf
    from sslcontext import SSLContext, is_pyopenssl
else:
    try:
        from OpenSSL import crypto as _crypto, SSL as _SSL
        from OpenSSL.crypto import _lib, _ffi, _new_mem_buf

        try:
            from sslcontext import is_pyopenssl
        except:

            def is_pyopenssl(ctx):
                if hasattr(ctx, "_ctx") and isinstance(ctx._ctx, _SSL.Context):
                    return True
                else:
                    return False

    except ImportError as e:
        _crypto = None

        def is_pyopenssl(ctx):
            return False

        from cryptography.hazmat.bindings.openssl.binding import Binding as _binding

        _binding = _binding()
        _ffi = _binding.ffi
        _lib = _binding.lib

        def _new_mem_buf(buffer=None):
            # Code from Openssl.crypto
            if buffer is None:
                bio = _lib.BIO_new(_lib.BIO_s_mem())
                free = _lib.BIO_free
            else:
                data = _ffi.new("char[]", buffer)
                bio = _lib.BIO_new_mem_buf(data, len(buffer))

                def free(bio, ref=data):
                    return _lib.BIO_free(bio)

            if bio == _ffi.NULL:
                raise Exception("Something wrong")
            bio = _ffi.gc(bio, free)
            return bio


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


ValidPath = Union[str, PathLike]
PasswordLike = Union[bytes, str, None, Callable[[], Union[str, bytes]]]

ProtectedByteEncoded = Tuple[bytes, Encoding, PasswordLike]
EncodedBytes = Union[Tuple[bytes, Encoding], ProtectedByteEncoded]
ProtectedEncodedFile = Union[
    Tuple[ValidPath, Encoding, PasswordLike], Tuple[ValidPath, PasswordLike]
]
EncodedFile = Union[Tuple[ValidPath, Encoding], ValidPath, ProtectedEncodedFile]
Encoded = Union[EncodedFile, EncodedBytes]


def _is_encoded_file(encoded: Encoded) -> _TypeGuard[EncodedFile]:
    return not isinstance(encoded, tuple) or not isinstance(encoded[0], bytes)


def _getEncryption(password: PasswordLike) -> _Encryption:
    password = _getPassword(password)
    if password is None:
        return _NoEncryption()
    else:
        return _TextEncryption(password)


def _getPassword(password: PasswordLike) -> "bytes|None":
    if password is None:
        return None
    elif isfunction(password):
        password = password()
    return _as_bytes(password) if password is not None else None


def _as_bytes(val, encoding: str = "utf-8") -> bytes:
    return val.encode(encoding) if isinstance(val, str) else val


class X509EncodedStore(ABC):
    def __new__(cls, encoded: Encoded):
        if _is_encoded_file(encoded):
            return _FileDecoder.new(encoded)
        else:
            return _ByteDecoder.new(encoded)

    @abstractstaticmethod
    def new(encoded: Encoded) -> "X509EncodedStore":
        ...

    @abstractproperty
    def encoding(self) -> bytes:
        ...

    @abstractproperty
    def encryption(self) -> PasswordLike:
        pass

    def raw_dump(self) -> "tuple[bytes, Encoding, PasswordLike]":
        with self as (io, encoding, password):
            return io.read(), encoding, password

    @abstractmethod
    def open(self) -> "tuple[BinaryIO, Encoding, PasswordLike]":
        pass

    @abstractmethod
    def close(self):
        pass

    def __enter__(self):
        return self.open()

    def __exit__(self, *args):
        self.close()

    def decode(self):
        with self as (io, encoding, password):
            yield from decode(io, encoding, password)
        return

    def load_key_and_certificates(self):
        with self as (io, encoding, password):
            return load_key_and_certificates(io, encoding, password)


class __ByteDecoder(NamedTuple):
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

    def raw_dump(self) -> "tuple[bytes, Encoding, PasswordLike]":
        return self

    def open(self):
        return (_BytesIO(self.data), self.encoding, self.encryption)

    def close(self):
        pass


class _ByteDecoder(__ByteDecoder, X509EncodedStore):
    ...


class __FileDecoder(NamedTuple):
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

    def open(self, mode: str = "rb"):
        self._io = self.path.open(mode)
        return (self._io, self.encoding, self.encryption)

    def close(self):
        return self._io.close()


class _FileDecoder(__FileDecoder, X509EncodedStore):
    ...


_ENCODING_SUFFIX_MAP: "dict[str,Encoding]" = {}
for t in Encoding:
    for e in t.exts():
        _ENCODING_SUFFIX_MAP["." + e] = t


class _X509Creds(NamedTuple):
    key: PrivateKey
    cert: Certificate
    chain: "list[Certificate]"

    @property
    def subject(self):
        return self.cert.subject


class _X509PubCreds(NamedTuple):
    cert: Certificate
    chain: "list[Certificate]"

    @property
    def subject(self):
        return self.cert.subject


def load_der(data: bytes, password: bytes = None):
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        return _load_der_private_key(data, password)


def load_der_certs(buffer: bytes):
    bundle_bio = _new_mem_buf(buffer)
    while True:
        try:
            _x509 = _lib.d2i_X509_bio(bundle_bio, _ffi.NULL)
            if _x509 == _ffi.NULL:
                break
            cert_bio = _new_mem_buf()
            if _lib.i2d_X509_bio(cert_bio, _x509) != 1:
                break
            cert_buffer = _ffi.new("char**")
            cert_len = _lib.BIO_get_mem_data(cert_bio, cert_buffer)
            yield x509.load_der_x509_certificate(
                _ffi.buffer(cert_buffer[0], cert_len)[:]
            )
        except Exception as e:
            break


def dump_der_archive(file: BinaryIO, store: "Iterable[Certificate|PrivateKey]"):
    with _tar.open(fileobj=file, mode="w") as bundle:
        for i, cert_or_key in enumerate(store):
            if isinstance(cert_or_key, Certificate):
                data = dump_cert(cert_or_key, Encoding.DER)
                suffix = "crt"
            else:
                data = dump_key(cert_or_key, Encoding.DER)
                suffix = "key"
            info = _tar.TarInfo(f"{i}.{suffix}.der")
            info.size = len(data)
            bundle.addfile(info, _BytesIO(data))


def load_der_archive(file: "BinaryIO|_tar.TarFile|bytes", password: bytes = None):
    def _load(file: _tar.TarFile):
        for member in file.getmembers():
            if member.name.endswith(".der"):
                yield load_der(file.extractfile(member).read(), password)

    if isinstance(file, _tar.TarFile):
        yield from _load(file)
    else:
        with _tar.open(
            fileobj=file if isinstance(file, bytes) else file, mode="r"
        ) as file:
            yield from _load(file)


def load_cert(data: bytes, encoding: Encoding, password: PasswordLike = None):
    password = _getPassword(password)
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
    password = _getPassword(password)
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


def iter_pem(pem: BinaryIO) -> Iterator[Tuple[str, bytes]]:
    sectionName = None
    sectionData = bytes()
    while True:
        line = pem.readline()
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


def decode_pem(pem: "BinaryIO|bytes", password: PasswordLike = None):
    for section, data in iter_pem(_BytesIO(pem) if isinstance(pem, bytes) else pem):
        if section == "CERTIFICATE" or section == "X509 CERTIFICATE":
            yield x509.load_pem_x509_certificate(data)
        elif "PRIVATE KEY" in section:
            yield _load_pem_private_key(data, password)


def load_certs(
    io: "bytes|BinaryIO", encoding: Encoding, password: PasswordLike = None
) -> "list[Certificate]":
    password = _getPassword(password)
    if encoding is Encoding.PKCS12:
        store = _pkcs12.load_pkcs12(
            io.read() if not isinstance(io, bytes) else io, password
        )
        return [store.cert.certificate] + store.additional_certs
    elif encoding is Encoding.PEM:
        certs = []
        for section, data in iter_pem(io):
            if section == "CERTIFICATE" or section == "X509 CERTIFICATE":
                certs.append(x509.load_pem_x509_certificate(data))
        return certs
    elif encoding is Encoding.DER:
        return list(load_der_certs(io.read() if not isinstance(io, bytes) else io))

    else:
        raise ValueError(f"Invalid encoding {encoding}")


def load_key_and_certificates(
    io: "bytes|BinaryIO", encoding: Encoding, password: PasswordLike = None
) -> "tuple[ PrivateKey|None, Certificate|None, list[Certificate]]":
    password = _getPassword(password)
    if encoding is Encoding.PKCS12:
        return _pkcs12.load_key_and_certificates(
            io.read() if not isinstance(io, bytes) else io, password
        )
    elif encoding is Encoding.PEM:
        key = None
        certs = []
        for section, data in iter_pem(io):
            if section == "CERTIFICATE" or section == "X509 CERTIFICATE":
                certs.append(x509.load_pem_x509_certificate(data))
            elif "PRIVATE KEY" in section:
                if key is None:
                    key = _load_pem_private_key(data, password)
                else:
                    raise ValueError("Found unexpected private key in PEM credentials")
            else:
                raise ValueError(f"Found unexpected section in PEM {section}")
        return key, certs[0], certs[1:]
    elif encoding is Encoding.DER:
        data =io.read() if not isinstance(io, bytes) else io
        certs = []
        key = None
        cert = None
        try:
            certs = list(load_der_certs(data))
            if len(certs) ==  1:
                cert = certs[0]
                certs = []
        except ValueError:
            pass
        if not certs:
            key = _load_der_private_key(data, password)
        return key, cert, certs
    else:
        raise ValueError(f"Invalid encoding {encoding}")


def decode(
    io: "BinaryIO|bytes", encoding: Encoding, password: PasswordLike = None
) -> "Iterator[PrivateKey|Certificate]":
    password = _getPassword(password)
    if encoding is Encoding.PKCS12:
        key, cert, chain = _pkcs12.load_key_and_certificates(
            io.read() if not isinstance(io, bytes) else io, password
        )
        yield cert
        yield key
        yield from chain
    elif encoding is Encoding.PEM:
        yield from decode_pem(io, password)
    elif encoding is Encoding.DER:
        data =io.read() if not isinstance(io, bytes) else io
        try:
            _load_der_private_key(data, password)
        except ValueError:
            yield from load_der_certs(data)
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


from ipaddress import ip_address as _ip, IPv4Address as _ipv4, IPv6Address as _ipv6

IPAddress = Tuple[_ipv4, _ipv6]


def into_ip(ip: str):
    try:
        return _ip(ip)
    except ValueError:
        return None


def parse_sans(sans: "Iterable[str|IPAddress|x509.GeneralName]"):
    _sans: "set[x509.GeneralName]" = set()
    for san in sans:
        if isinstance(san, x509.GeneralName):
            _sans.add(san)
            continue
        ip = into_ip(san)
        if ip:
            _sans.add(x509.IPAddress(ip))
        _sans.add(x509.DNSName(san))
    return _sans


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
    purpose = purpose or CertPurpose._

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
        key_usage.update({"key_cert_sign": True, "crl_sign": True})
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
    issuer: "_X509Creds|tuple[PrivateKey,x509.Name|Certificate|_X509PubCreds]",
    hash_alg: HashAlgorithm = None,
):
    key, name = issuer
    if isinstance(name, x509.Name):
        name = name
    else:
        name = name.subject
    return (
        builder.issuer_name(name)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hash_alg or DEF_HASH_ALG)
    )
