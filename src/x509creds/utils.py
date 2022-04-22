from cryptography.x509 import (
    Extension,
    ExtensionType,
    ObjectIdentifier,
    CertificateBuilder,
    oid,
)
from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256, HashAlgorithm
from typing_extensions import (
    TypeAlias as _Alias,
    Literal as _Literal,
    TypeGuard as _TypeGuard,
)
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from typing import TYPE_CHECKING, Any, Iterable as _Iter, overload
from enum import IntFlag as _IntFlag
from datetime import timedelta, datetime

from ipaddress import ip_address as _ip, IPv4Address as _ipv4, IPv6Address as _ipv6

from ._vendor.crypto import *
from ._models import _X509Credentials, _X509Identity

ExtensionLike: _Alias = (
    "Extension| tuple[ExtensionType, bool]|tuple[ObjectIdentifier, ExtensionType, bool]"
)
KeyUsage = _Literal[
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
_IPAddress: _Alias = "tuple[_ipv4, _ipv6]"

DEF_KEY_SIZE = 2048
DEF_PUBLIC_EXPONENT = 65537
CERT_MAX_AGE = timedelta(seconds=397 * 24 * 60 * 60)
DEF_HASH_ALG = _SHA256()


class CertPurpose(_IntFlag):
    _ = 0
    CA = 1
    CLIENT = 2
    SERVER = 4


def is_public_key(key: "PrivateKey|PublicKey") -> _TypeGuard[PublicKey]:
    return hasattr(key, "public_bytes")


def parse_extension(ext_like: ExtensionLike) -> Extension:
    if isinstance(ext_like, Extension):
        return ext_like
    elif isinstance(ext_like, ExtensionType):
        return Extension(oid=ext_like.oid, value=ext_like, critical=False)
    elif len(ext_like) == 2:
        return Extension(oid=ext_like[0].oid, value=ext_like, critical=ext_like[1])
    else:
        return Extension(oid=ext_like[0], value=ext_like[1], critical=ext_like[2])


def into_ip(ip: str):
    try:
        return _ip(ip)
    except ValueError:
        return None


def parse_sans(sans: "_Iter[str|_IPAddress|x509.GeneralName]"):
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
    extensions: _Iter[ExtensionLike] = None,
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
    extensions: _Iter[ExtensionLike] = None,
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
    extensions: _Iter[ExtensionLike] = None,
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
        ext_key_usage.append(oid.ExtendedKeyUsageOID.SERVER_AUTH)

    if CertPurpose.CLIENT in purpose:
        key_usage["key_agreement"] = True
        key_usage["key_encipherment"] = True
        ext_key_usage.append(oid.ExtendedKeyUsageOID.CLIENT_AUTH)

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
    issuer: "_X509Credentials|tuple[PrivateKey,x509.Name|Certificate|_X509Identity]",
    hash_alg: HashAlgorithm = None,
):
    name = issuer[1]
    key = issuer[0]
    if not isinstance(name, x509.Name):
        name = name.subject
    return (
        builder.issuer_name(name)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hash_alg or DEF_HASH_ALG)
    )
