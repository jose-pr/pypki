from ipaddress import IPv4Address, IPv6Address
from typing import Callable, Generic, Iterable, Literal, overload
from pathlib import Path
from cryptography.hazmat.primitives.hashes import HashAlgorithm, SHA256
from x509creds import X509Credentials, Encoding, x509
from datetime import datetime, timedelta

from .utils import cert_builder, into_ip
from .cache import T, Cache, FileCache, LRUCache

CERT_NOT_AFTER = 397 * 24 * 60 * 60

CERTS_DIR = "./ca/certs/"

CERT_NAME = "certauth sample CA"

DEF_HASH_FUNC = SHA256()

DEF_ENCODING = Encoding.PEM

ROOT_CA = "!!root_ca"


# =================================================================
class CertificateAuthority(Generic[T]):
    """
    Utility class for signing individual certificate
    with a root cert.

    Static generate_ca_root() method for creating the root cert

    All certs saved on filesystem. Individual certs are stored
    in specified certs_dir and reused if previously created.
    """

    credentials: X509Credentials
    cache: Cache[str, str, X509Credentials, T]

    def __init__(
        self,
        credentials: "X509Credentials|str|tuple[str, str|None, str|None]",
        cache: "Cache[str, str, X509Credentials, T]|None" = None,
        cert_not_before: "timedelta|int" = 0,
        cert_not_after: "timedelta|int" = CERT_NOT_AFTER,
        encoding: "Literal[Encoding.PEM,Encoding.PKCS12]|None" = None,
        store_password: str = None,
        hash: "HashAlgorithm|None" = None,
        transform: "Callable[[X509Credentials], T]" = lambda x: x,
    ):
        self.hash = hash or DEF_HASH_FUNC
        self.encoding = encoding or DEF_ENCODING
        self.cert_not_before = (
            timedelta(seconds=cert_not_before)
            if isinstance(cert_not_before, int)
            else cert_not_before
        )
        self.cert_not_after = (
            timedelta(seconds=cert_not_after)
            if isinstance(cert_not_after, int)
            else cert_not_after
        )
        self._root_creds_new = False

        if isinstance(credentials, str):
            credentials = (credentials, None, None)
        if isinstance(credentials[0], str):
            path = Path(credentials[0])
            name = credentials[1] if credentials[1] else path.stem
            password = credentials[2]
            try:
                encoding = Encoding.from_suffix(path.suffix)
            except:
                encoding = self.encoding

            if path.exists():
                credentials = X509Credentials.load(
                    cert=(path.read_bytes(), encoding), password=password
                )
            else:
                builder, key = self._cert_builder(name, True)
                cert = builder.sign(key, self.hash)
                credentials = X509Credentials(cert, key, [])
                path.write_bytes(credentials.dump(encoding, password))
                self._root_creds_new = True

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
        if isinstance(cache, str):
            _suffix = "." + self.encoding.exts()[0]

            def as_bytes(creds: X509Credentials) -> "list[bytes]":
                return [creds.dump(self.encoding, password=store_password)]

            def from_bytes(data: Iterable[bytes]) -> T:
                creds = X509Credentials.load(
                    (next(data), self.encoding), password=store_password
                )
                return transform(creds)

            def stored_as(host: str):
                return [host.replace(":", "-") + _suffix]

            self.cache = FileCache[str, X509Credentials, T](
                cache, as_bytes=as_bytes, from_bytes=from_bytes, stored_as=stored_as
            )
        elif isinstance(cache, int):
            self.cache = LRUCache(max_size=cache, transform=transform)
        elif cache is None:
            self.cache = LRUCache(max_size=100, transform=transform)
        else:
            self.cache = cache

    @overload
    def load_cert(
        self,
        host: str,
        overwrite: bool = False,
        include_cache_key: Literal[True] = True,
        sans: "Iterable[str|IPv6Address|IPv4Address]|None" = None,
    ) -> "tuple[T, str]":
        ...

    @overload
    def load_cert(
        self,
        host: str,
        overwrite: bool = False,
        include_cache_key: Literal[False] = False,
        sans: "Iterable[str|IPv6Address|IPv4Address]|None" = None,
    ) -> T:
        ...

    def load_cert(
        self,
        host: str,
        overwrite: bool = False,
        include_cache_key: bool = False,
        sans: "Iterable[str|IPv6Address|IPv4Address]|None" = None,
    ):

        sans = sans or []

        creds = None

        if not overwrite:
            creds = self.cache.get(host)

        if not creds:
            # if not cached, generate new root or host cert
            creds = self.generate_host_cert(
                host,
                sans=sans,
            )
            # store cert in cache
            self.cache[host] = creds
            creds = self.cache[host]

        if not include_cache_key:
            return creds

        else:
            cache_key = self.cache.stored_as(host)
            if cache_key and not isinstance(cache_key, str):
                cache_key = str(cache_key)

            return creds, cache_key

    def cert_for_host(
        self,
        host: str,
        overwrite=False,
        sans: "Iterable[str|IPv6Address|IPv4Address]|None" = None,
    ):

        res = self.load_cert(
            host,
            overwrite=overwrite,
            include_cache_key=True,
            sans=sans,
        )

        return res[1]

    def _cert_builder(self, certname, root=False):
        builder, key = cert_builder(
            certname, issuer=None if root else self.credentials.cert
        )
        start = datetime.now() + self.cert_not_before
        builder = builder.not_valid_before(start).not_valid_after(
            start + self.cert_not_after
        )
        return builder, key

    def generate_host_cert(
        self,
        host,
        sans: "Iterable[str|IPv6Address|IPv4Address]|None" = None,
    ):

        builder, key = self._cert_builder(host)
        _done = []
        _sans = []
        for san in [host, *sans]:
            ip = into_ip(san)
            san = str(san)
            if san not in _done:
                if ip:
                    _sans.append(x509.IPAddress(ip))
                _sans.append(x509.DNSName(san))
                _done.append(san)

        builder = builder.add_extension(x509.SubjectAlternativeName(_sans), False)
        cert = builder.sign(self.credentials.key, self.hash)
        return X509Credentials(cert, key, [self.credentials.cert])
