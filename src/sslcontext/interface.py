from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Iterable
import sys
import os
from ._vendor.imports import SSLContext as NativeSSLContext, PyOpenSSLCtx
from ._vendor import ssl as _ssl
import warnings as _warnings
from socket import socket as _socket

if TYPE_CHECKING:
    from ssl import _SSLMethod as SSLMethod, Options, VerifyMode
    from socket import socket
    import OpenSSL.SSL


class SSLSocket(ABC):
    """API-compatibility interface for Python Connection-class.

    Note: _makefile_refs, _drop() and _reuse() are needed for the garbage
    collector of pypy.
    """

    def __init__(self) -> None:
        super().__init__()
        self._io_refs: int = 0
        self._closed = False

    @abstractmethod
    def fileno(self) -> int:
        raise NotImplementedError()

    @abstractmethod
    def recv(self, bufsize: int, flags: int = ...) -> bytes:
        raise NotImplementedError()

    @abstractmethod
    def recv_into(self, buffer, nbytes: int = ..., flags: int = ...) -> int:
        raise NotImplementedError()

    @abstractmethod
    def settimeout(self, timeout: "float|None") -> None:
        raise NotImplementedError()

    @abstractmethod
    def sendall(self, data, flags: int = ...) -> None:
        raise NotImplementedError()

    @abstractmethod
    def shutdown(self):
        raise NotImplementedError()

    @abstractmethod
    def getpeercert(self, binary_form: bool = False) -> dict:
        raise NotImplementedError()

    @abstractmethod
    def version(self):
        raise NotImplementedError()

    @abstractmethod
    def _real_close(self):
        ...

    def _reuse(self):
        self._io_refs += 1
        
    _decref_socketios = _drop = _socket._decref_socketios
    close = _socket.close
    makefile = _socket.makefile


class SSLContext(ABC):
    """
    I am a abstract class that deines an interface of the standard library ``SSLContext`` object.
    """

    if os.name == "nt":
        _windows_cert_stores = _ssl.WINDOWS_TRUSTED_STORES

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
        cadata: "bytes|str|None" = None,
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
        sock: "socket",
        server_side=False,
        do_handshake_on_connect=True,
        suppress_ragged_eofs=True,
        server_hostname: "str|None" = None,
    ) -> SSLSocket:
        ...

    def _load_windows_store_certs(
        self, storename: str, purpose: _ssl.Purpose = _ssl.Purpose.SERVER_AUTH
    ):
        certs = bytearray()
        try:
            count = 0
            for cert, encoding, trust in _ssl.enum_certificates(storename):
                # CA certs are never PKCS#7 encoded
                if encoding == "x509_asn":
                    if trust is True or purpose.oid in trust:
                        certs.extend(cert)
                        count += 1
        except PermissionError:
            _warnings.warn("unable to enumerate Windows certificate store")
        if certs:
            self.load_verify_locations(cadata=certs)
        return certs

    def load_default_certs(self, purpose=_ssl.Purpose.SERVER_AUTH):
        if sys.platform == "win32":
            for storename in self._windows_cert_stores:
                self._load_windows_store_certs(storename, purpose)
        self.set_default_verify_paths()

    @property
    def pyopenssl(self) -> "OpenSSL.SSL.Context|None":
        """
        May not be avialable but if it is it should return a OpenSSL.SSL.Context
        """
        return None


class SSLContextProvider(ABC):
    def sslcontext(self, protocol: "SSLMethod") -> SSLContext:
        factory = None
        if NativeSSLContext:
            factory = NativeSSLContext
        else:
            if PyOpenSSLCtx:
                from ._vendor.pyopenssl import PyOpenSSLContext
            factory = PyOpenSSLContext
        if factory:
            return factory(protocol)
        else:
            raise Exception("Could not load a module that provides a SSLContext")
