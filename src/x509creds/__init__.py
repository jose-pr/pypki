from abc import ABC as _ABC, abstractmethod as _abstractmethod
from typing import (
    TYPE_CHECKING,
    overload,
    Literal as _Literal,
    Iterable as _Iter,
    Mapping as _Mapping,
)

import tempfile as _tmp
import os as _os

from ._vendor.pyopenssl import get_pyopenssl_ctx, _crypto
from ._vendor.crypto import *
from .encoding import (
    Encoding,
    X509EncodedStore,
    pem as _pem,
    der as _der,
    pkcs12 as _pkcs12,
    _Encoding,
    Encoded,
    PasswordLike
)
from .encoding._decoders import ValidPath
from ._models import _X509Credentials, _X509Identity
from .utils import (
    CertPurpose,
    ExtensionLike,
    KeyUsage,
    cert_builder,
    generate_certificate,
    is_public_key,
    DatetimeRef,
    _IPAddress as IPAddress
)

if TYPE_CHECKING:
    from sslcontext import SSLContext


class X509Issuer(_ABC):
    @_abstractmethod
    def sign(
        self, builder: CertificateBuilder, hash_alg: HashAlgorithm
    ) -> "X509Identity":
        ...

    @overload
    def generate(
        self,
        subject: "x509.Name|str",
        key: "PrivateKey|int|None" = None,
        purpose: CertPurpose = None,
        not_before: DatetimeRef = None,
        not_after: DatetimeRef = None,
        extensions: _Iter[ExtensionLike] = None,
        key_usage: "_Mapping[KeyUsage,bool]" = None,
        ext_key_usage: "list" = None,
        hash_alg: HashAlgorithm = None,
    ) -> "X509Credentials":
        ...

    @overload
    def generate(
        self,
        subject: "x509.Name|str",
        key: "PublicKey" = None,
        purpose: CertPurpose = None,
        not_before: DatetimeRef = None,
        not_after: DatetimeRef = None,
        extensions: "_Iter[ExtensionLike]" = None,
        key_usage: "_Mapping[KeyUsage,bool]" = None,
        ext_key_usage: "list" = None,
        hash_alg: HashAlgorithm = None,
    ) -> "X509Identity":
        ...

    def generate(
        self,
        subject: "x509.Name|str",
        key: "PrivateKey|PublicKey|int|None" = None,
        purpose: CertPurpose = None,
        not_before: DatetimeRef = None,
        not_after: DatetimeRef = None,
        extensions: _Iter[ExtensionLike] = None,
        key_usage: "_Mapping[KeyUsage,bool]" = None,
        ext_key_usage: "list" = None,
        hash_alg: HashAlgorithm = None,
    ):
        return create_creds(
            subject,
            key,
            self,
            purpose,
            not_before,
            not_after,
            extensions,
            key_usage,
            ext_key_usage,
            hash_alg,
        )


class X509Identity(_X509Identity):
    @overload
    def dump(self, encoding: _Literal[Encoding.PEM, Encoding.PKCS12]) -> bytes:
        pass

    @overload
    def dump(self, encoding: _Literal[Encoding.DER]) -> "tuple[bytes, list[bytes]]":
        pass

    def dump(self, encoding: Encoding):
        encoding
        if encoding is Encoding.DER:
            return (
                self.cert.public_bytes(_Encoding.DER),
                [ca.public_bytes(_Encoding.DER) for ca in self.chain],
            )
        elif encoding is Encoding.PEM:
            return _pem.dump(None, *self)
        elif encoding is Encoding.PKCS12:
            return _pkcs12.dump(None, *self)
        else:
            raise ValueError(f"Invalid encoding {encoding}")

    @staticmethod
    def load(*stores: "Encoded"):
        self = load_creds(*stores)
        if isinstance(self, X509Credentials):
            return self.public
        else:
            return self

    @staticmethod
    def create(
        subject: "x509.Name|str",
        key: "PublicKey|PrivateKey" = None,
        issuer: "X509Issuer|None" = None,
        purpose: CertPurpose = None,
        not_before: DatetimeRef = None,
        not_after: DatetimeRef = None,
        extensions: _Iter[ExtensionLike] = None,
        key_usage: "_Mapping[KeyUsage,bool]" = None,
        ext_key_usage: "list" = None,
        hash_alg: HashAlgorithm = None,
    ):
        creds = create_creds(
            subject,
            key,
            issuer,
            purpose,
            not_before,
            not_after,
            extensions,
            key_usage,
            ext_key_usage,
            hash_alg,
        )
        if isinstance(creds, X509Credentials):
            return creds.public
        else:
            return creds

    def apply_to_sslcontext(self, sslcontext: "SSLContext"):
        pyopenssl = get_pyopenssl_ctx(sslcontext)
        if pyopenssl:
            crt, chain = self.to_pyopenssl()
            store = pyopenssl.get_cert_store()
            store.add_cert(crt)
            for ca in chain:
                store.add_cert(ca)
            return

        pem = self.dump(Encoding.PEM)
        fd, path = _tmp.mkstemp()
        try:
            with _os.fdopen(fd, "wb") as tmp:
                tmp.write(pem)
            sslcontext.load_verify_locations(cafile=path)
        finally:
            _os.remove(path)

    if _crypto:

        def to_pyopenssl(self):
            return (
                _crypto.X509.from_cryptography(self.cert),
                [_crypto.X509.from_cryptography(ca) for ca in self.chain],
            )

        @staticmethod
        def from_pyopenssl(
            cert: _crypto.X509,
            chain: _Iter[_crypto.X509] = [],
        ):
            return from_pyopenssl(cert, chain)


class X509Credentials(_X509Credentials, X509Issuer):
    @overload
    def dump(
        self, encoding: _Literal[Encoding.PEM, Encoding.PKCS12], password: str = None
    ) -> bytes:
        pass

    @overload
    def dump(
        self, encoding: _Literal[Encoding.DER], password: str = None
    ) -> "tuple[bytes, bytes, list[bytes]]":
        pass

    def dump(self, encoding: Encoding, password: str = None):

        if encoding is Encoding.DER:
            return _der.dump(*self, password)
        elif encoding is Encoding.PEM:
            return _pem.dump(*self, password)
        elif encoding is Encoding.PKCS12:
            return _pkcs12.dump(*self, password)
        else:
            raise ValueError(f"Invalid encoding {encoding}")

    @staticmethod
    def load(*stores: Encoded):
        self = load_creds(*stores)
        if isinstance(self, X509Credentials):
            return self
        else:
            raise ValueError("No Private Key Avalaible")

    def sign(
        self, builder: CertificateBuilder, hash_alg: HashAlgorithm = None
    ) -> X509Identity:
        return X509Identity(
            generate_certificate(builder, self, hash_alg),
            [self.cert, *self.chain],
        )

    @property
    def public(self):
        return X509Identity(self.cert, self.chain)

    @staticmethod
    def create(
        subject: "x509.Name|str",
        key: "PrivateKey|int|None" = None,
        issuer: "X509Issuer|None" = None,
        purpose: CertPurpose = None,
        not_before: DatetimeRef = None,
        not_after: DatetimeRef = None,
        extensions: _Iter[ExtensionLike] = None,
        key_usage: "_Mapping[KeyUsage,bool]" = None,
        ext_key_usage: "list" = None,
        hash_alg: HashAlgorithm = None,
    ):
        if is_public_key(key):
            raise ValueError("Provided key is a public key")
        return create_creds(
            subject,
            key,
            issuer,
            purpose,
            not_before,
            not_after,
            extensions,
            key_usage,
            ext_key_usage,
            hash_alg,
        )

    def apply_to_sslcontext(self, sslcontext: "SSLContext"):
        pyopenssl = get_pyopenssl_ctx(sslcontext)
        if cert:
            key, cert, chain = self.to_pyopenssl()
            store = pyopenssl.get_cert_store()
            store.add_cert(cert)
            for ca in chain:
                store.add_cert(ca)
            pyopenssl.use_certificate(cert)
            pyopenssl.use_privatekey(key)
            return

        pem = self.dump(Encoding.PEM)
        fd, path = _tmp.mkstemp()
        try:
            with _os.fdopen(fd, "wb") as tmp:
                tmp.write(pem)
            sslcontext.load_cert_chain(certfile=path)
        finally:
            _os.remove(path)

    if _crypto:

        def to_pyopenssl(self):
            return (
                _crypto.load_privatekey(_crypto.FILETYPE_PEM, _pem.dump_key(self.key)),
                _crypto.X509.from_cryptography(self.cert),
                [_crypto.X509.from_cryptography(ca) for ca in self.chain],
            )

        @staticmethod
        def from_pyopenssl(
            key: _crypto.PKey,
            cert: _crypto.X509,
            chain: _Iter[_crypto.X509] = [],
        ):
            return from_pyopenssl(key, cert, chain)


if _crypto:

    @overload
    def from_pyopenssl(
        cert: _crypto.X509, chain: _Iter[_crypto.X509] = [], /
    ) -> X509Identity:
        ...

    @overload
    def from_pyopenssl(
        key: None, cert: _crypto.X509, chain: _Iter[_crypto.X509] = [], /
    ) -> X509Identity:
        ...

    @overload
    def from_pyopenssl(
        key: _crypto.PKey, cert: _crypto.X509, chain: _Iter[_crypto.X509] = [], /
    ) -> X509Credentials:
        ...

    def from_pyopenssl(*args):
        cert: _crypto.X509
        key: "None|_crypto.PKey"
        chain: _Iter[_crypto.X509]
        if isinstance(args[0], _crypto.X509):
            cert, chain = args
            key = None
        else:
            key, cert, chain = args
        return (
            X509Credentials(
                key.to_cryptography_key(),
                cert.to_cryptography(),
                [ca.to_cryptography() for ca in (chain or [])],
            )
            if key
            else X509Identity(
                cert.to_cryptography(), [ca.to_cryptography() for ca in (chain or [])]
            )
        )


def load_creds(*stores: Encoded):
    key = None
    cert = None
    chain = []
    for store in stores:
        for decoded in X509EncodedStore(store):
            if isinstance(decoded, Certificate):
                if cert is None:
                    cert = decoded
                else:
                    chain.append(decoded)
            else:
                if key is None:
                    key = decoded

    if cert is None:
        raise ValueError("No certificate was found")
    return X509Credentials(key, cert, chain) if key else X509Identity(cert, chain)


@overload
def create_creds(
    subject: "x509.Name|str",
    key: "PrivateKey|int|None" = None,
    issuer: "X509Issuer|None" = None,
    purpose: CertPurpose = None,
    not_before: DatetimeRef = None,
    not_after: DatetimeRef = None,
    extensions: _Iter[ExtensionLike] = None,
    key_usage: "_Mapping[KeyUsage,bool]" = None,
    ext_key_usage: "list" = None,
    hash_alg: HashAlgorithm = None,
) -> X509Credentials:
    ...


@overload
def create_creds(
    subject: "x509.Name|str",
    key: "PublicKey" = None,
    issuer: "X509Issuer|None" = None,
    purpose: CertPurpose = None,
    not_before: DatetimeRef = None,
    not_after: DatetimeRef = None,
    extensions: _Iter[ExtensionLike] = None,
    key_usage: "_Mapping[KeyUsage,bool]" = None,
    ext_key_usage: "list" = None,
    hash_alg: HashAlgorithm = None,
) -> X509Identity:
    ...


def create_creds(
    subject: "x509.Name|str",
    key: "PrivateKey|PublicKey|int|None" = None,
    issuer: "X509Issuer|None" = None,
    purpose: CertPurpose = None,
    not_before: DatetimeRef = None,
    not_after: DatetimeRef = None,
    extensions: _Iter[ExtensionLike] = None,
    key_usage: "_Mapping[KeyUsage,bool]" = None,
    ext_key_usage: "list" = None,
    hash_alg: HashAlgorithm = None,
):
    builder = cert_builder(
        subject,
        key,
        purpose,
        not_before,
        not_after,
        extensions,
        key_usage,
        ext_key_usage,
    )
    if not isinstance(builder, CertificateBuilder):
        builder, key = builder
    if issuer is None:
        cert = generate_certificate(builder, (key, builder._subject_name), hash_alg)
        chain = []
    else:
        cert, chain = issuer.sign(builder, hash_alg)

    if is_public_key(key):
        return X509Identity(cert, chain)
    else:
        return X509Credentials(key, cert, chain)
