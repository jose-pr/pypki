from io import FileIO
from typing import Iterator, overload
from x509creds import X509Credentials, Encoding, ValidPath

from .store import FileStore, FilePathStore, LRUCache, Transform, T, Store

CredentialsStore = Store[str, X509Credentials, T]


def _ondiskStoreFuncs(
    encoding: "Encoding|None" = None,
    password: str = None,
    transform: Transform[X509Credentials, T] = None,
):
    encoding: Encoding = encoding or Encoding.PKCS12
    transform = transform or (lambda x: x)
    _suffix = "." + encoding.exts()[0]

    def dump(iterio: Iterator[FileIO], creds: X509Credentials):
        if encoding is Encoding.DER:
            encoded = creds.dump(encoding, password)
            next(iterio).write(encoded[1])
            next(iterio).write(encoded[0])
            chain_io = next(iterio)
            for ca in encoded[2]:
                chain_io.write(ca)
        else:
            encoded = creds.dump(encoding, password)
            next(iterio).write(encoded)

    def load(iterio: Iterator[FileIO]) -> T:
        creds = X509Credentials.load(
            *[(src.read(), encoding, password) for src in iterio]
        )
        return transform(creds)

    def stored_as(host: str):
        base = host.replace(":", "-")
        if encoding is Encoding.DER:
            return [base + ".crt.der", base + ".key.der", base + ".chain.der"]
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
