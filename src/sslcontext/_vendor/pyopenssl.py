# Copy/Pasted from urllib3.contrib.pyopenssl, python 2 code eliminated, idna optional
"""
TLS with SNI_-support for Python 2. Follow these instructions if you would
like to verify TLS certificates in Python 2. Note, the default libraries do
*not* do certificate checking; you need to do additional work to validate
certificates yourself.

This needs the following packages installed:

* `pyOpenSSL`_ (tested with 16.0.0)
* `cryptography`_ (minimum 1.3.4, from pyopenssl) Verify?

However, pyopenssl depends on cryptography, which depends on idna, so while we
use all three directly here we end up having relatively few packages required.

You can install them with the following command:

.. code-block:: bash

    $ python -m pip install pyopenssl cryptography
"""
from __future__ import absolute_import

import OpenSSL.SSL
from OpenSSL import crypto
from cryptography import x509
from socket import error as SocketError
from socket import timeout

from .wait import wait_for_read, wait_for_write

import logging
from .ssl import *

# Map from urllib3 to PyOpenSSL compatible parameter-values.
_openssl_versions = {
    PROTOCOL_TLS: OpenSSL.SSL.SSLv23_METHOD,
    PROTOCOL_TLS_CLIENT: OpenSSL.SSL.SSLv23_METHOD,
    PROTOCOL_TLSv1: OpenSSL.SSL.TLSv1_METHOD,
}

_stdlib_to_openssl_verify = {
    VerifyMode.CERT_NONE: OpenSSL.SSL.VERIFY_NONE,
    VerifyMode.CERT_OPTIONAL: OpenSSL.SSL.VERIFY_PEER,
    VerifyMode.CERT_REQUIRED: OpenSSL.SSL.VERIFY_PEER
    + OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
}
_openssl_to_stdlib_verify = dict((v, k) for k, v in _stdlib_to_openssl_verify.items())

# OpenSSL will only write 16K at a time
SSL_WRITE_BLOCKSIZE = 16384

log = logging.getLogger(__name__)

try:
    import idna

    def _idna_encode(name: str) -> bytes:
        """
        Borrowed wholesale from the Python Cryptography Project. It turns out
        that we can't just safely call `idna.encode`: it can explode for
        wildcard names. This avoids that problem.
        """
        try:
            for prefix in ["*.", "."]:
                if name.startswith(prefix):
                    name = name[len(prefix) :]
                    return prefix.encode("ascii") + idna.encode(name)
            return idna.encode(name)
        except idna.core.IDNAError:
            return None

except ImportError:
    import encodings

    def _idna_encode(name: str) -> bytes:
        try:
            return encodings.search_function("idna").encode(name)[0]
        except:
            return None


def _dnsname_to_stdlib(name):
    """
    Converts a dNSName SubjectAlternativeName field to the form used by the
    standard library on the given Python version.

    Cryptography produces a dNSName as a unicode string that was idna-decoded
    from ASCII bytes. We need to idna-encode that string to get it back, and
    then on Python 3 we also need to convert to unicode via UTF-8 (the stdlib
    uses PyUnicode_FromStringAndSize on it, which decodes via UTF-8).

    If the name cannot be idna-encoded then we return None signalling that
    the name given should be skipped.
    """

    # Don't send IPv6 addresses through the IDNA encoder.
    if ":" in name:
        return name

    name = _idna_encode(name)
    if name is None:
        return None
    else:
        name = name.decode("utf-8")
    return name


def get_subj_alt_name(peer_cert: crypto.X509):
    """
    Given an PyOpenSSL certificate, provides all the subject alternative names.
    """

    cert = peer_cert.to_cryptography()

    # We want to find the SAN extension. Ask Cryptography to locate it (it's
    # faster than looping in Python)
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        # No such extension, return the empty list.
        return []
    except (
        x509.DuplicateExtension,
        x509.UnsupportedGeneralNameType,
        UnicodeError,
    ) as e:
        # A problem has been found with the quality of the certificate. Assume
        # no SAN field is present.
        log.warning(
            "A problem was encountered with the certificate that prevented "
            "cryptography from finding the SubjectAlternativeName field. This can "
            "affect certificate validation. The error was %s",
            e,
        )
        return []

    # We want to return dNSName and iPAddress fields. We need to cast the IPs
    # back to strings because the match_hostname function wants them as
    # strings.
    # Sadly the DNS names need to be idna encoded and then, on Python 3, UTF-8
    # decoded. This is pretty frustrating, but that's what the standard library
    # does with certificates, and so we need to attempt to do the same.
    # We also want to skip over names which cannot be idna encoded.
    names = [
        ("DNS", name)
        for name in map(_dnsname_to_stdlib, ext.get_values_for_type(x509.DNSName))
        if name is not None
    ]
    names.extend(
        ("IP Address", str(name)) for name in ext.get_values_for_type(x509.IPAddress)
    )

    return names


from ..interface import SSLSocket, SSLContext


class PyOpenSSLSocket(SSLSocket):
    """API-compatibility wrapper for Python OpenSSL's Connection-class.

    Note: _makefile_refs, _drop() and _reuse() are needed for the garbage
    collector of pypy.
    """

    def __init__(
        self,
        connection: OpenSSL.SSL.Connection,
        suppress_ragged_eofs=True,
    ):
        self.connection = connection
        self.suppress_ragged_eofs = suppress_ragged_eofs
        super().__init__()

    def _handle_read_err(self, e: OpenSSL.SSL.Error):
        if isinstance(e, OpenSSL.SSL.SysCallError):
            if not self.suppress_ragged_eofs and e.args == (-1, "Unexpected EOF"):
                raise SocketError(str(e))
        elif isinstance(e, OpenSSL.SSL.ZeroReturnError):
            if not self.connection.get_shutdown() == OpenSSL.SSL.RECEIVED_SHUTDOWN:
                raise
        elif isinstance(e, OpenSSL.SSL.WantReadError):
            if not wait_for_read(self, self.gettimeout()):
                raise timeout("The read operation timed out")
            else:
                return True
        elif isinstance(e, OpenSSL.SSL.WantWriteError):
            if not wait_for_write(self, self.gettimeout()):
                raise timeout()
        else:
            raise SSLError("read error: %r" % e)

    def do_hanshake(self):
        while True:
            try:
                self.connection.do_handshake()
            except OpenSSL.SSL.WantReadError:
                if not wait_for_read(self, self.gettimeout()):
                    raise timeout("select timed out")
                continue
            except OpenSSL.SSL.Error as e:
                raise SSLError("bad handshake: %r" % e)
            break

    def recv(self, *args, **kwargs):
        try:
            data = self.connection.recv(*args, **kwargs)
        except OpenSSL.SSL.Error as e:
            if self._handle_read_err(e):
                return self.recv(*args, **kwargs)
            else:
                return b""
        else:
            return data

    def recv_into(self, *args, **kwargs):
        try:
            return self.connection.recv_into(*args, **kwargs)
        except OpenSSL.SSL.Error as e:
            if self._handle_read_err(e):
                return self.recv_into(*args, **kwargs)
            else:
                return 0

    def _send(self, data):
        while True:
            try:
                return self.connection.send(data)
            except OpenSSL.SSL.WantWriteError:
                if not wait_for_write(self, self.gettimeout()):
                    raise timeout()
                continue
            except OpenSSL.SSL.SysCallError as e:
                raise SocketError(str(e))

    def sendall(self, data):
        total_sent = 0
        while total_sent < len(data):
            sent = self._send(data[total_sent : total_sent + SSL_WRITE_BLOCKSIZE])
            total_sent += sent

    def getpeercert(self, binary_form=False):
        x509 = self.connection.get_peer_certificate()

        if not x509:
            return x509

        if binary_form:
            return crypto.dump_certificate(crypto.FILETYPE_ASN1, x509)

        return {
            "subject": ((("commonName", x509.get_subject().CN),),),
            "subjectAltName": get_subj_alt_name(x509),
        }

    def version(self):
        return self.connection.get_protocol_version_name()

    def __getattr__(self, name):
        """
        Look up attributes on the wrapped socket object if they are not found
        on the Connection object.
        """
        return getattr(self.connection, name)

    def _real_close(self):
        return self.connection.close()

    def fileno(self) -> int:
        self.connection.fileno()

    def settimeout(self, timeout: "float|None") -> None:
        self.connection.settimeout(timeout)

    def sendall(self, data, flags: int = ...) -> None:
        self.connection.sendall(data, flags)

    def shutdown(self):
        self.connection.shutdown()


class PyOpenSSLContext(SSLContext):
    """
    I am a wrapper class for the PyOpenSSL ``Context`` object. I am responsible
    for translating the interface of the standard library ``SSLContext`` object
    to calls into PyOpenSSL.
    """

    def __init__(self, protocol):
        self.protocol = _openssl_versions[protocol]
        self._ctx = OpenSSL.SSL.Context(self.protocol)
        self._options = 0
        self.check_hostname = False

    @property
    def options(self):
        return self._options

    @options.setter
    def options(self, value):
        self._options = value
        self._ctx.set_options(value)

    @property
    def verify_mode(self):
        return _openssl_to_stdlib_verify[self._ctx.get_verify_mode()]

    @verify_mode.setter
    def verify_mode(self, value):
        self._ctx.set_verify(_stdlib_to_openssl_verify[value], _verify_callback)

    def set_default_verify_paths(self):
        self._ctx.set_default_verify_paths()

    def set_ciphers(self, ciphers):
        if isinstance(ciphers, str):
            ciphers = ciphers.encode("utf-8")
        self._ctx.set_cipher_list(ciphers)

    def load_verify_locations(self, cafile=None, capath=None, cadata=None):
        if cafile is not None:
            cafile = cafile.encode("utf-8")
        if capath is not None:
            capath = capath.encode("utf-8")
        try:
            if capath or cafile:
                self._ctx.load_verify_locations(cafile, capath)
            if cadata is not None:
                if isinstance(cadata, str):
                    data = cadata.encode("ascii")
                    encoding = crypto.FILETYPE_PEM
                else:
                    data = bytes(cadata)
                    encoding = crypto.FILETYPE_ASN1
                _load_ca_certs(encoding, data, self._ctx)
        except OpenSSL.SSL.Error as e:
            raise SSLError("unable to load trusted certificates: %r" % e)

    def load_cert_chain(self, certfile, keyfile=None, password=None):
        self._ctx.use_certificate_chain_file(certfile)
        if password is not None:
            if not isinstance(password, bytes):
                password = password.encode("utf-8")
            self._ctx.set_passwd_cb(lambda *_: password)
        self._ctx.use_privatekey_file(keyfile or certfile)

    def set_alpn_protocols(self, protocols):
        protocols = [ensure_binary(p) for p in protocols]
        return self._ctx.set_alpn_protos(protocols)

    def wrap_socket(
        self,
        sock,
        server_side=False,
        do_handshake_on_connect=True,
        suppress_ragged_eofs=True,
        server_hostname=None,
    ):
        cnx = OpenSSL.SSL.Connection(self._ctx, sock)

        if isinstance(server_hostname, str):
            server_hostname = server_hostname.encode("utf-8")

        if server_hostname is not None:
            cnx.set_tlsext_host_name(server_hostname)

        if server_side:
            cnx.set_accept_state()
        else:
            cnx.set_connect_state()

        socket = PyOpenSSLSocket(cnx, suppress_ragged_eofs)
        if do_handshake_on_connect:
            socket.do_hanshake()

        return socket

    @property
    def pyopenssl(self) -> "OpenSSL.SSL.Context":
        return self._ctx


def ensure_binary(s: str, encoding="utf-8", errors="strict"):
    if isinstance(s, bytes):
        return s
    if isinstance(s, str):
        return s.encode(encoding, errors)


def _verify_callback(cnx, x509, err_no, err_depth, return_code):
    return err_no == 0


# adapted from cpython impl to load cdata
def _load_ca_certs(type: int, buffer: bytes, context: OpenSSL.SSL.Context):
    bio = crypto._new_mem_buf(buffer)
    store = crypto._lib.SSL_CTX_get_cert_store(context._context)
    if store == crypto._ffi.NULL:
        raise Exception("Could not load store for OpenSSL.SSL.Context")
    count = 0
    while True:
        if type == crypto.FILETYPE_PEM:
            x509 = crypto._lib.PEM_read_bio_X509(
                bio, crypto._ffi.NULL, crypto._ffi.NULL, crypto._ffi.NULL
            )
        elif type == crypto.FILETYPE_ASN1:
            x509 = crypto._lib.d2i_X509_bio(bio, crypto._ffi.NULL)
        else:
            raise ValueError("type argument must be FILETYPE_PEM or FILETYPE_ASN1")

        if x509 == crypto._ffi.NULL:
            break
        count += 1
        if not crypto._lib.X509_STORE_add_cert(store, x509):
            raise Exception(f"Could not cert #{count} to the store")
        crypto._lib.X509_free(x509)
    return count
