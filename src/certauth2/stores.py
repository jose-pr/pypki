from io import BytesIO, FileIO
from os import PathLike
from typing import Union, Iterator, overload
from x509creds import X509Credentials, Encoding
import tarfile


from .cache import FileCache, FileStorage, LRUCache, Transform, T

_Path = Union[str, PathLike]


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
            cert, key, chain = creds.dump(encoding, password=password)
            next(iterio).write(cert)
            next(iterio).write(key)
            with tarfile.open(fileobj=next(iterio), mode="w") as bundle:
                for i, ca in enumerate(chain):
                    ca_io = BytesIO(ca)
                    ca_info = tarfile.TarInfo(f"{i}.crt.der")
                    ca_info.size = len(ca)
                    bundle.addfile(ca_info, ca_io)
        else:
            next(iterio).write(creds.dump(encoding, password=password))

    def load(iterio: Iterator[FileIO]) -> T:
        if encoding is Encoding.DER:
            cert = next(iterio).read()
            key = next(iterio).read()
            chain = []
            with tarfile.open(fileobj=next(iterio), mode="r") as bundle:
                for member in bundle.getmembers():
                    if member.name.endswith(".crt.der"):
                        chain.append((bundle.extractfile(member).read(), encoding))

            creds = X509Credentials.load(
                (cert, encoding), (key, encoding), chain, password=password
            )
        else:
            creds = X509Credentials.load(
                (next(iterio).read(), encoding), password=password
            )
        return transform(creds)

    def stored_as(host: str):
        if encoding is Encoding.DER:
            base = host.replace(":", "-")
            return [base + ".crt.der", base + ".key.der", base + ".trust_chain.der.tar"]
        return [host.replace(":", "-") + _suffix]

    return dump, load, stored_as


@overload
def ondiskCredentialStore(
    directory: _Path, encoding: "Encoding|None" = None, password: str = None
) -> FileCache[str, X509Credentials, X509Credentials]:
    ...


def ondiskCredentialStore(
    directory: _Path,
    encoding: "Encoding|None" = None,
    password: str = None,
    transform: Transform[X509Credentials, T] = None,
):
    dump, load, stored_as = _ondiskStoreFuncs(encoding, password, transform)

    return FileCache[str, X509Credentials, T](
        directory, load=load, dump=dump, stored_as=stored_as
    )


@overload
def ondisPathStore(
    directory: _Path, encoding: "Encoding|None" = None, password: str = None
) -> FileStorage[str, X509Credentials, X509Credentials]:
    ...


def ondiskPathStore(
    directory: _Path,
    encoding: "Encoding|None" = None,
    password: str = None,
    transform: Transform[X509Credentials, T] = None,
):
    dump, load, stored_as = _ondiskStoreFuncs(encoding, password, transform)
    return FileStorage[str, X509Credentials, T](
        directory, load=load, dump=dump, stored_as=stored_as, transform=transform
    )


def onMemoryCredentialStore(
    max_size: int, transform: Transform[X509Credentials, T] = None
):
    transform = transform or (lambda x: x)
    return LRUCache[str, X509Credentials, T](max_size, transform=transform)
