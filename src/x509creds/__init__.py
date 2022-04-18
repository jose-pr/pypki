from abc import ABC as _ABC, abstractmethod as _abstractmethod
from functools import reduce as _reduce

from .utils import *
from .utils import (
    _crypto,
    _NoEncryption,
    _TextEncryption,
    _Encoding,
    _PrivateFormat,
    _pkcs12,
    _X509Creds,
    _X509PubCreds,
)
import tempfile as _tmp
import os as _os


class X509PublicCredentials(_X509PubCreds):
    @overload
    def dump(self, encoding: Literal[Encoding.PEM, Encoding.PKCS12]) -> bytes:
        pass

    @overload
    def dump(self, encoding: Literal[Encoding.DER]) -> "tuple[bytes, list[bytes]]":
        pass

    def dump(self, encoding: Encoding):

        if encoding is Encoding.DER:
            return (
                self.cert.public_bytes(_Encoding.DER),
                [ca.public_bytes(_Encoding.DER) for ca in self.chain],
            )
        elif encoding is Encoding.PEM:
            return _reduce(
                lambda acc, cert: acc + cert.public_bytes(_Encoding.PEM),
                self.chain,
                self.cert.public_bytes(_Encoding.PEM),
            )
        elif encoding is Encoding.PKCS12:
            return _pkcs12.serialize_key_and_certificates(
                self.cert.subject.rfc4514_string(),
                None,
                self.cert,
                self.chain,
                _NoEncryption(),
            )
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
        not_before: "datetime|int|timedelta" = None,
        not_after: "datetime|int|timedelta" = None,
        extensions: Iterable[ExtensionLike] = None,
        key_usage: "dict[KeyUsage,bool]" = None,
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

        if is_pyopenssl(sslcontext):
            crt, chain = self.to_pyopenssl()
            for ca in [crt, *chain]:
                sslcontext._ctx.add_extra_chain_cert(ca)
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
            chain: Iterable[_crypto.X509] = [],
        ):
            return from_pyopenssl(cert, chain)


class X509Issuer(_ABC):
    @_abstractmethod
    def sign(
        self, builder: CertificateBuilder, hash_alg: HashAlgorithm
    ) -> X509PublicCredentials:
        ...

    @overload
    def generate(
        self,
        subject: "x509.Name|str",
        key: "PrivateKey|int|None" = None,
        purpose: CertPurpose = None,
        not_before: "datetime|int|timedelta" = None,
        not_after: "datetime|int|timedelta" = None,
        extensions: Iterable[ExtensionLike] = None,
        key_usage: "dict[KeyUsage,bool]" = None,
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
        not_before: "datetime|int|timedelta" = None,
        not_after: "datetime|int|timedelta" = None,
        extensions: "Iterable[ExtensionLike]" = None,
        key_usage: "dict[KeyUsage,bool]" = None,
        ext_key_usage: "list" = None,
        hash_alg: HashAlgorithm = None,
    ) -> "X509PublicCredentials":
        ...

    def generate(
        self,
        subject: "x509.Name|str",
        key: "PrivateKey|PublicKey|int|None" = None,
        purpose: CertPurpose = None,
        not_before: "datetime|int|timedelta" = None,
        not_after: "datetime|int|timedelta" = None,
        extensions: Iterable[ExtensionLike] = None,
        key_usage: "dict[KeyUsage,bool]" = None,
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


class X509Credentials(_X509Creds, X509Issuer):
    @overload
    def dump(
        self, encoding: Literal[Encoding.PEM, Encoding.PKCS12], password: str = None
    ) -> bytes:
        pass

    @overload
    def dump(
        self, encoding: Literal[Encoding.DER], password: str = None
    ) -> "tuple[bytes, bytes, list[bytes]]":
        pass

    def dump(self, encoding: Encoding, password: str = None):
        encryption = (
            _NoEncryption() if password is None else _TextEncryption(password.encode())
        )
        if encoding is Encoding.DER:
            return (
                self.key.private_bytes(_Encoding.DER, _PrivateFormat.PKCS8, encryption),
                self.cert.public_bytes(_Encoding.DER),
                [ca.public_bytes(_Encoding.DER) for ca in self.chain],
            )
        elif encoding is Encoding.PEM:
            return self.key.private_bytes(
                _Encoding.PEM, _PrivateFormat.PKCS8, encryption
            ) + _reduce(
                lambda acc, cert: acc + cert.public_bytes(_Encoding.PEM),
                self.chain,
                self.cert.public_bytes(_Encoding.PEM),
            )
        elif encoding is Encoding.PKCS12:
            return _pkcs12.serialize_key_and_certificates(
                self.cert.subject.rfc4514_string(),
                self.key,
                self.cert,
                self.chain,
                encryption,
            )
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
    ) -> X509PublicCredentials:
        return X509PublicCredentials(
            generate_certificate(builder, self, hash_alg),
            [self.cert, *self.chain],
        )

    @property
    def public(self):
        return X509PublicCredentials(self.cert, self.chain)

    @staticmethod
    def create(
        subject: "x509.Name|str",
        key: "PrivateKey|int|None" = None,
        issuer: "X509Issuer|None" = None,
        purpose: CertPurpose = None,
        not_before: "datetime|int|timedelta" = None,
        not_after: "datetime|int|timedelta" = None,
        extensions: Iterable[ExtensionLike] = None,
        key_usage: "dict[KeyUsage,bool]" = None,
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
        if is_pyopenssl(sslcontext):
            key, cert, chain = self.to_pyopenssl()
            for ca in chain:
                sslcontext._ctx.add_extra_chain_cert(ca)
            sslcontext._ctx.use_certificate(cert)
            sslcontext._ctx.use_privatekey(key)
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
            key = dump_key(self.key, Encoding.PEM)
            return (
                _crypto.load_privatekey(_crypto.FILETYPE_PEM, key),
                _crypto.X509.from_cryptography(self.cert),
                [_crypto.X509.from_cryptography(ca) for ca in self.chain],
            )

        @staticmethod
        def from_pyopenssl(
            key: _crypto.PKey,
            cert: _crypto.X509,
            chain: Iterable[_crypto.X509] = [],
        ):
            return from_pyopenssl(key, cert, chain)


if _crypto:

    @overload
    def from_pyopenssl(
        cert: _crypto.X509, chain: Iterable[_crypto.X509] = [], /
    ) -> X509PublicCredentials:
        ...

    @overload
    def from_pyopenssl(
        key: None, cert: _crypto.X509, chain: Iterable[_crypto.X509] = [], /
    ) -> X509PublicCredentials:
        ...

    @overload
    def from_pyopenssl(
        key: _crypto.PKey, cert: _crypto.X509, chain: Iterable[_crypto.X509] = [], /
    ) -> X509Credentials:
        ...

    def from_pyopenssl(*args):
        cert: _crypto.X509
        key: "None|_crypto.PKey"
        chain: Iterable[_crypto.X509]
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
            else X509PublicCredentials(
                cert.to_cryptography(), [ca.to_cryptography() for ca in (chain or [])]
            )
        )


def load_creds(*stores: Encoded):
    key = None
    cert = None
    chain = []
    for store in stores:
        for decoded in X509EncodedStore(store).decode():
            if isinstance(decoded, Certificate):
                if cert is None:
                    cert = decoded
                else:
                    chain.append(cert)
            else:
                if key is None:
                    key = decoded

    if cert is None:
        raise ValueError("No certificate was found")
    return (
        X509Credentials(key, cert, chain) if key else X509PublicCredentials(cert, chain)
    )


@overload
def create_creds(
    subject: "x509.Name|str",
    key: "PrivateKey|int|None" = None,
    issuer: "X509Issuer|None" = None,
    purpose: CertPurpose = None,
    not_before: "datetime|int|timedelta" = None,
    not_after: "datetime|int|timedelta" = None,
    extensions: Iterable[ExtensionLike] = None,
    key_usage: "dict[KeyUsage,bool]" = None,
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
    not_before: "datetime|int|timedelta" = None,
    not_after: "datetime|int|timedelta" = None,
    extensions: Iterable[ExtensionLike] = None,
    key_usage: "dict[KeyUsage,bool]" = None,
    ext_key_usage: "list" = None,
    hash_alg: HashAlgorithm = None,
) -> X509PublicCredentials:
    ...


def create_creds(
    subject: "x509.Name|str",
    key: "PrivateKey|PublicKey|int|None" = None,
    issuer: "X509Issuer|None" = None,
    purpose: CertPurpose = None,
    not_before: "datetime|int|timedelta" = None,
    not_after: "datetime|int|timedelta" = None,
    extensions: Iterable[ExtensionLike] = None,
    key_usage: "dict[KeyUsage,bool]" = None,
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
        return X509PublicCredentials(cert, chain)
    else:
        return X509Credentials(key, cert, chain)
