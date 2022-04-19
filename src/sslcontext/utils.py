from itertools import count
from typing import TYPE_CHECKING, Sequence
import os, sys
import warnings

if TYPE_CHECKING:
    from .interface import SSLContext
from ._vendor.ssl import Purpose, VerifyMode
from ._vendor.imports import SSLContext as NativeSSLContext, PyOpenSSLCtx

if os.name == "nt":
    _windows_cert_stores = ("CA", "ROOT")

    try:
        from ssl import enum_certificates
    except:
        import wincertstore as _store

        def enum_certificates(storename: str) -> "tuple[bytes, str, bool|str]":
            store = _store.CertSystemStore(storename)
            try:
                cert: _store.CERT_CONTEXT
                for cert in store.itercerts():
                    yield cert.get_encoded(), "x509_asn" if cert.encoding_type == "CERTIFICATE" else cert.encoding_type, cert.enhanced_keyusage()
            finally:
                store.close()

    # from ssl builtin
    def load_windows_store_certs(
        ctx: "SSLContext", storename: str, purpose: Purpose = Purpose.SERVER_AUTH
    ):
        certs = bytearray()
        try:
            count = 0
            for cert, encoding, trust in enum_certificates(storename):
                # CA certs are never PKCS#7 encoded
                if encoding == "x509_asn":
                    if trust is True or purpose.oid in trust:
                        certs.extend(cert)
                        count += 1
            print(count)
        except PermissionError:
            warnings.warn("unable to enumerate Windows certificate store")
        if certs:
            ctx.load_verify_locations(cadata=certs)
        return certs


def load_default_certs(ctx: "SSLContext", purpose=Purpose.SERVER_AUTH):
    if sys.platform == "win32":
        for storename in _windows_cert_stores:
            load_windows_store_certs(ctx, storename, purpose)
    ctx.set_default_verify_paths()


def set_sslcontext_defaults(
    context: "SSLContext",
    purpose=Purpose.SERVER_AUTH,
    *,
    cafile=None,
    capath=None,
    cadata=None
):

    if purpose == Purpose.SERVER_AUTH:
        # verify certs and host name in client mode
        context.verify_mode = VerifyMode.CERT_REQUIRED
        context.check_hostname = True

    if cafile or capath or cadata:
        context.load_verify_locations(cafile, capath, cadata)
    elif context.verify_mode != VerifyMode.CERT_NONE:
        # no explicit cafile, capath or cadata but the verify mode is
        # CERT_OPTIONAL or CERT_REQUIRED. Let's try to load default system
        # root CA certificates for the given purpose. This may fail silently.
        load_default_certs(context, purpose)
    # OpenSSL 1.1.1 keylog file
    if hasattr(context, "keylog_filename"):
        keylogfile = os.environ.get("SSLKEYLOGFILE")
        if keylogfile and not sys.flags.ignore_environment:
            context.keylog_filename = keylogfile
    return context

def is_pyopenssl(ctx: 'SSLContext'):
    if PyOpenSSLCtx and hasattr(ctx, "pyopenssl") and isinstance(ctx.pyopenssl(), PyOpenSSLCtx):
        return True
    else:
        return False

def get_pyopenssl_ctx(sslcontext: 'SSLContext'):
    if hasattr(sslcontext, "pyopenssl"):
        return sslcontext.pyopenssl()