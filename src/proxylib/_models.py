from abc import ABC
from socket import getservbyname
from typing import Iterable, NamedTuple, overload

from ._re import _URI_REGEX


class _URI(NamedTuple):
    scheme: str
    username: str
    password: str
    host: str
    port: "int|None"

    @property
    def netloc(self):
        if self.port:
            return f"{self.host}:{self.port}"
        else:
            return self.host

    def resolved(self):
        if self.port:
            return self
        else:
            self.__class__(
                self.scheme,
                self.username,
                self.password,
                self.host,
                getservbyname(self.scheme),
            )

    @classmethod
    def from_str(cls, uri: str):
        return cls(*_URI_REGEX.match(uri).groups()) if uri else None


class URL(_URI):
    _DEFAULT_SCHEME = "http"

    def __new__(
        cls, scheme: str, username: str, password: str, host: str, port: str
    ) -> "Proxy":
        scheme = scheme.lower()
        if not scheme:
            scheme = cls._DEFAULT_SCHEME

        if port:
            port = int(port)

        return super().__new__(cls, scheme, username, password, host, port)


class Proxy(_URI):
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

        if port:
            port = int(port)

        return super().__new__(cls, scheme, username, password, host, port)

    @staticmethod
    def from_uris(uri: str):
        return set([Proxy(*proxy) for proxy in _URI_REGEX.findall(uri)] if uri else [])


class Proxy(_URI):
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

        if port:
            port = int(port)

        return super().__new__(cls, scheme, username, password, host, port)

    @staticmethod
    def from_uris(uri: str):
        return set([Proxy(*proxy) for proxy in _URI_REGEX.findall(uri)] if uri else [])


class ProxyMap(ABC):
    @overload
    def __getitem__(self, uri: str) -> Iterable[Proxy]:
        pass
