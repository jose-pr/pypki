from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from ssl import _SSLMethod as SSLMethod, Options, VerifyMode
    from socket import socket


class SSLSocket(ABC):
    """API-compatibility interface for Python Connection-class.

    Note: _makefile_refs, _drop() and _reuse() are needed for the garbage
    collector of pypy.
    """

    @abstractmethod
    def fileno(self) -> int:
        ...

    @abstractmethod
    def recv(self, bufsize: int, flags: int = ...) -> bytes:
        ...

    @abstractmethod
    def recv_into(self, buffer, nbytes: int = ..., flags: int = ...) -> int:
        ...

    @abstractmethod
    def settimeout(self, timeout: "float|None") -> None:
        ...

    @abstractmethod
    def sendall(self, data, flags: int = ...) -> None:
        ...

    @abstractmethod
    def shutdown(self):
        ...

    @abstractmethod
    def close(self):
        ...

    @abstractmethod
    def getpeercert(self, binary_form: bool = False) -> dict:
        ...

    @abstractmethod
    def version(self):
        ...

    @abstractmethod
    def _reuse(self):
        ...

    @abstractmethod
    def _drop(self):
        ...

    _makefile_refs: int


class SSLContext(ABC):
    """
    I am a abstract class that deines an interface of the standard library ``SSLContext`` object.
    """

    @abstractmethod
    def __init__(self, protocol: "SSLMethod"):
        ...

    options: "Options"
    verify_mode: "VerifyMode"

    @abstractmethod
    def set_default_verify_paths(self):
        ...

    @abstractmethod
    def set_ciphers(self, ciphers: str):
        ...

    @abstractmethod
    def load_verify_locations(
        self,
        cafile: "str|None" = None,
        capath: "str|None" = None,
        cadata: "str|None" = None,
    ):
        ...

    @abstractmethod
    def load_cert_chain(
        self, certfile: str, keyfile: "str|None" = None, password: "str|None" = None
    ):
        ...

    @abstractmethod
    def set_alpn_protocols(self, protocols: "Iterable[bytes|str]"):
        ...

    @abstractmethod
    def wrap_socket(
        self,
        sock:'socket',
        server_side=False,
        do_handshake_on_connect=True,
        suppress_ragged_eofs=True,
        server_hostname: "str|None" = None,
    ) -> SSLSocket:
        ...


class SSLContextProvider(ABC):
    def sslcontext(self, protocol: "SSLMethod") -> SSLContext:
        errs = []
        try:
            from ssl import SSLContext
        except BaseException as e:
            errs.append(e)
            SSLContext = None
        if SSLContext is None:
            try:
                from ._vendor.pyopenssl import PyOpenSSLContext as SSLContext
            except BaseException as e:
                errs.append(e)
                pass
        if SSLContext:
            return SSLContext(protocol)
        else:
            raise Exception("Could not load a module that provides a SSLContext", errs)