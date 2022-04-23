from abc import ABC
from socket import getservbyname
from typing import Iterable, NamedTuple, overload

from ._uri import _URI_REGEX


class _Proxy(NamedTuple):
    scheme: str
    username: str
    password: str
    host: str
    port: "int|None"


class Proxy(_Proxy):
    _DEFAULT_SCHEME = "http"

    def __new__(
        cls, scheme: str, username: str, password: str, host: str, port: str
    ) -> "Proxy":
        scheme = scheme.lower()
        if scheme == "direct":
            return None
        elif scheme == "proxy":
            scheme = "http"
        elif scheme == "socks":
            scheme = "socks4"
        elif not scheme:
            scheme = cls._DEFAULT_SCHEME

        if not port:
            port = getservbyname(scheme)
        else:
            port = int(port)
        return super().__new__(cls, scheme, username, password, host, port)

    @staticmethod
    def from_uris(uri: str):
        return set([Proxy(*proxy) for proxy in _URI_REGEX.findall(uri)] if uri else [])


class ProxyMap(ABC):
    @overload
    def __getitem__(self) -> Iterable[Proxy]:
        pass
