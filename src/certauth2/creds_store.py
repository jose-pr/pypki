from io import FileIO
from typing import Iterator, overload
from x509creds import (
    X509Credentials,
    Encoding,
    ValidPath,
    load_der_archive,
    dump_der_archive,
    dump_cert,
    dump_key,
)
from x509creds.utils import load_der


from .store import FileStore, FilePathStore, LRUCache, Transform, T, Store

CredentialsStore = Store[str, X509Credentials, T]


def _ondiskStoreFuncs(
    encoding: "Encoding|None" = None,
    password: str = None,
    transform: Transform[X509Credentials, T] = None,
):
    encoding = encoding or Encoding.PKCS12
    transform = transform or (lambda x: x)
    _suffix = "." + encoding.exts()[0]

    def dump(iterio: Iterator[FileIO], creds: X509Credentials):
        if encoding is Encoding.DER:
            next(iterio).write(dump_cert(creds.cert, encoding))
            next(iterio).write(dump_key(creds.key, encoding, password))
            dump_der_archive(next(iterio), creds.chain)
        else:
            next(iterio).write(creds.dump(encoding, password=password))

    def load(iterio: Iterator[FileIO]) -> T:
        if encoding is Encoding.DER:
            cert = load_der(next(iterio).read())
            key = load_der(next(iterio).read(), password)
            chain = list(load_der_archive(next(iterio), password))
            creds = X509Credentials(key, cert, chain)
        else:
            creds = X509Credentials.load((next(iterio).read(), encoding, password))
        return transform(creds)

    def stored_as(host: str):
        base = host.replace(":", "-")
        if encoding is Encoding.DER:
            return [base + ".crt.der", base + ".key.der", base + ".chain.der.tar"]
        return [base + _suffix]

    return dump, load, stored_as


@overload
def ondiskCredentialStore(
    directory: ValidPath, encoding: "Encoding|None" = None, password: str = None
) -> FileStore[str, X509Credentials, X509Credentials]:
    ...


def ondiskCredentialStore(
    directory: ValidPath,
    encoding: "Encoding|None" = None,
    password: str = None,
    transform: Transform[X509Credentials, T] = None,
):
    dump, load, stored_as = _ondiskStoreFuncs(encoding, password, transform)

    return FileStore[str, X509Credentials, T](
        directory, load=load, dump=dump, stored_as=stored_as
    )


@overload
def ondiskPathStore(
    directory: ValidPath, encoding: "Encoding|None" = None, password: str = None
) -> FilePathStore[str, X509Credentials, X509Credentials]:
    ...


def ondiskPathStore(
    directory: ValidPath,
    encoding: "Encoding|None" = None,
    password: str = None,
    transform: Transform[X509Credentials, T] = None,
):
    dump, load, stored_as = _ondiskStoreFuncs(encoding, password, transform)
    return FilePathStore[str, X509Credentials, T](
        directory, load=load, dump=dump, stored_as=stored_as
    )


def onMemoryCredentialStore(
    max_size: int, transform: Transform[X509Credentials, T] = None
):
    transform = transform or (lambda x: x)
    return LRUCache[str, X509Credentials, T](max_size, transform=transform)
