from abc import ABC, abstractmethod
from functools import reduce

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
            return reduce(
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

    if _crypto:

        def to_pyopenssl(self):
            data = self.dump(Encoding.PEM)

            certs: "list[_crypto.X509]" = []
            for section, data in parse_pem(data):
                if section == "CERTIFICATE":
                    certs.append(_crypto.load_certificate(_crypto.FILETYPE_PEM, data))

            return (
                certs[0],
                certs[1:],
            )

        @staticmethod
        def from_pyopenssl(
            cert: _crypto.X509,
            chain: Iterable[_crypto.X509] = [],
        ):
            return from_pyopenssl(cert, None, chain)


class X509Issuer(ABC):
    @abstractmethod
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
                self.cert.public_bytes(_Encoding.DER),
                self.key.private_bytes(_Encoding.DER, _PrivateFormat.PKCS8, encryption),
                [ca.public_bytes(_Encoding.DER) for ca in self.chain],
            )
        elif encoding is Encoding.PEM:
            return self.key.private_bytes(
                _Encoding.PEM, _PrivateFormat.PKCS8, encryption
            ) + reduce(
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
            generate_certificate(builder, self, hash_alg or DEF_HASH_ALG),
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

    if _crypto:

        def to_pyopenssl(self):
            data = self.dump(Encoding.PEM)

            key: "_crypto.PKey" = None
            certs: "list[_crypto.X509]" = []
            for section, data in parse_pem(data):
                if section == "CERTIFICATE":
                    certs.append(_crypto.load_certificate(_crypto.FILETYPE_PEM, data))
                elif "PRIVATE KEY" in section and key is None:
                    key = _crypto.load_privatekey(_crypto.FILETYPE_PEM, data)

            return (
                certs[0],
                key,
                certs[1:],
            )

        @staticmethod
        def from_pyopenssl(
            cert: _crypto.X509,
            key: _crypto.PKey,
            chain: Iterable[_crypto.X509] = [],
        ):
            return from_pyopenssl(cert, key, chain)


if _crypto:

    @overload
    def from_pyopenssl(
        cert: _crypto.X509,
        key: Literal[None] = None,
        chain: Iterable[_crypto.X509] = [],
    ) -> X509PublicCredentials:
        ...

    @overload
    def from_pyopenssl(
        cert: _crypto.X509, key: _crypto.PKey, chain: Iterable[_crypto.X509] = []
    ) -> X509Credentials:
        ...

    def from_pyopenssl(
        cert: _crypto.X509,
        key: "None|_crypto.PKey" = None,
        chain: Iterable[_crypto.X509] = [],
    ):
        return (
            X509Credentials(
                cert.to_cryptography(),
                key.to_cryptography_key(),
                [ca.to_cryptography() for ca in chain],
            )
            if key
            else X509PublicCredentials(
                cert.to_cryptography(), [ca.to_cryptography() for ca in chain]
            )
        )


def load_creds(*stores: Encoded):
    key = None
    cert = None
    chain = []
    for store in stores:
        _cert, _key, _chain = X509EncodedStore(store).decode()
        if _key and key is None:
            key = _key
        if _cert:
            if cert is None:
                cert = _cert
            else:
                chain.append(cert)
        chain.extend(_chain)
    if cert is None:
        raise ValueError("No certificate was found")
    return (
        X509Credentials(cert, key, _chain)
        if key
        else X509PublicCredentials(cert, _chain)
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
        cert = generate_certificate(builder, (builder._subject_name, key), hash_alg)
        chain = []
    else:
        cert, chain = issuer.sign(builder, hash_alg)

    if is_public_key(key):
        return X509PublicCredentials(cert, chain)
    else:
        return X509Credentials(cert, key, chain)
