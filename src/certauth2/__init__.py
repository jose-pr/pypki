from os import PathLike
from typing import Generic, Iterable, Mapping, overload
from pathlib import Path
from x509creds import (
    CertPurpose,
    KeyUsage,
    X509Credentials,
    Encoding,
    X509Issuer,
    X509PublicCredentials,
    x509,
    PublicKey,
    PrivateKey,
    HashAlgorithm,
    ValidPath,
    IPAddress,
)
from datetime import datetime, timedelta

from x509creds.utils import parse_sans

from .utils import is_ip, get_wildcard_domain
from .store import T
from .creds_store import (
    ondiskCredentialStore,
    onMemoryCredentialStore,
    CredentialsStore,
)


class CertificateAuthority(X509Issuer, Generic[T]):
    """
    Utility class for signing individual certificate
    with a provided CA or auto created self-signed root cert.
    """

    credentials: X509Credentials
    store: CredentialsStore[T]

    @overload
    def __new__(
        self,
        credentials: "X509Credentials|ValidPath|tuple[ValidPath, str|None, str|None]",
        store: "int|ValidPath|None" = None,
        cert_not_before: "timedelta|int|datetime" = None,
        cert_not_after: "timedelta|int|datetime" = None,
        hash: "HashAlgorithm|None" = None,
        verify_tld: bool = True,
        domain_cert: bool = False,
    ) -> "CertificateAuthority[X509Credentials]":
        ...
    @overload
    def __new__(
        self,
        credentials: "X509Credentials|ValidPath|tuple[ValidPath, str|None, str|None]",
        store: "CredentialsStore[T]" = None,
        cert_not_before: "timedelta|int|datetime" = None,
        cert_not_after: "timedelta|int|datetime" = None,
        hash: "HashAlgorithm|None" = None,
        verify_tld: bool = True,
        domain_cert: bool = False,
    ) -> "CertificateAuthority[T]":
        ...

    def __new__(cls, *args, **kwds):
        return super().__new__(cls, *args, **kwds)

    def __init__(
        self,
        credentials: "X509Credentials|ValidPath|tuple[ValidPath, str|None, str|None]",
        store: "CredentialsStore[T]|int|ValidPath|None" = None,
        cert_not_before: "timedelta|int|datetime" = None,
        cert_not_after: "timedelta|int|datetime" = None,
        hash: "HashAlgorithm|None" = None,
        verify_tld: bool = True,
        domain_cert: bool = False,
    ):
        self.hash = hash
        self.cert_not_before = cert_not_before
        self.cert_not_after = cert_not_after
        self._ca_created = self._modified = False
        self.verify_tld = verify_tld
        self.domain_cert = domain_cert

        if isinstance(credentials, str):
            credentials = (credentials, None, None)
        if isinstance(credentials[0], str):
            path = Path(credentials[0])
            name = credentials[1] if credentials[1] else path.stem
            password = credentials[2]
            encoding = Encoding.from_suffix(path.suffix)

            if path.exists():
                credentials = X509Credentials.load((path, encoding, password))
            else:
                credentials = X509Credentials.create(
                    name,
                    purpose=CertPurpose.CA,
                    not_before=self.cert_not_before,
                    not_after=self.cert_not_after,
                    hash_alg=self.hash,
                )
                path.write_bytes(credentials.dump(encoding, password))
                self._ca_created = True

            if (
                credentials[1]
                and credentials.cert.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME
                )[0].value
                != name
            ):
                raise ValueError(
                    "CN of existing certificate doesnt match requested name"
                )

        self.credentials = credentials
        if isinstance(store, (str, PathLike)):
            self.store = ondiskCredentialStore(store)
        elif isinstance(store, int):
            self.store = onMemoryCredentialStore(store)
        elif store is None:
            self.store = onMemoryCredentialStore(100)
        else:
            self.store = store

    def load_creds(
        self,
        host: str,
        overwrite: bool = False,
        domain_cert: bool = None,
        sans: "Iterable[str|IPAddress]|None" = None,
        **builder_kargs
    ):

        creds = None
        domain_cert = self.domain_cert if domain_cert is None else domain_cert

        if domain_cert and not host.startswith("*") and not is_ip(host):
            host = "*." + get_wildcard_domain(host, self.verify_tld)

        if not overwrite:
            creds = self.store.get(host)

        if not creds:
            sans = [host, *(sans or [])]
            self._modified = True
            creds = self.generate_host_creds(host, sans=sans, **builder_kargs)
            self.store[host] = creds
            creds = self.store[host]
        else:
            self._modified = False

        return creds

    def sign(self, builder: x509.CertificateBuilder, hash_alg: HashAlgorithm = None):
        return self.credentials.sign(builder, hash_alg or self.hash)

    @overload
    def generate(
        self,
        subject: "x509.Name|str",
        key: "PublicKey" = None,
        purpose: CertPurpose = None,
        not_before: "datetime|int|timedelta" = None,
        not_after: "datetime|int|timedelta" = None,
        extensions: Iterable[x509.Extension] = None,
        key_usage: "dict[KeyUsage,bool]" = None,
        ext_key_usage: "list" = None,
        hash_alg: HashAlgorithm = None,
    ) -> "X509PublicCredentials":
        ...

    @overload
    def generate(
        self,
        subject: "x509.Name|str",
        key: "PrivateKey|int|None" = None,
        purpose: CertPurpose = None,
        not_before: "datetime|int|timedelta" = None,
        not_after: "datetime|int|timedelta" = None,
        extensions: Iterable[x509.Extension] = None,
        key_usage: "dict[KeyUsage,bool]" = None,
        ext_key_usage: "list" = None,
        hash_alg: HashAlgorithm = None,
    ) -> X509Credentials:
        ...

    def generate(
        self,
        subject: "x509.Name|str",
        key: "PrivateKey|PublicKey|int|None" = None,
        purpose: CertPurpose = None,
        not_before: "datetime|int|timedelta" = None,
        not_after: "datetime|int|timedelta" = None,
        extensions: Iterable[x509.Extension] = None,
        key_usage: "dict[KeyUsage,bool]" = None,
        ext_key_usage: "list" = None,
        hash_alg: HashAlgorithm = None,
    ) -> "X509Credentials|X509PublicCredentials":
        return super().generate(
            subject,
            key,
            purpose,
            not_before or self.cert_not_before,
            not_after or self.cert_not_after,
            extensions,
            key_usage,
            ext_key_usage,
            hash_alg,
        )

    @overload
    def generate_host_creds(
        self,
        host: str,
        sans: "Iterable[str|IPAddress]|None" = None,
        key: "PublicKey" = None,
        **builder_kargs
    ) -> "X509PublicCredentials":
        ...

    def generate_host_creds(
        self, host: str, sans: "Iterable[str|IPAddress]|None" = None, **builder_kargs
    ) -> X509Credentials:

        extensions: list = builder_kargs.setdefault("extensions", [])
        extensions.append(x509.SubjectAlternativeName(parse_sans(sans or [])))
        builder_kargs["purpose"] = CertPurpose.SERVER | CertPurpose.CLIENT
        return self.generate(
            host,
            **builder_kargs,
        )

    def __getitem__(self, host: "str|dict"):
        if isinstance(host, str):
            return self.load_creds(host)
        elif isinstance(host, Mapping):
            return self.load_creds(**host)
        else:
            raise KeyError(host)
