from typing import TYPE_CHECKING
import os, sys

if TYPE_CHECKING:
    from .interface import SSLContext
from ._vendor.ssl import Purpose, VerifyMode
from ._vendor.imports import PyOpenSSLCtx


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
        context.load_default_certs(purpose)
    # OpenSSL 1.1.1 keylog file
    if hasattr(context, "keylog_filename"):
        keylogfile = os.environ.get("SSLKEYLOGFILE")
        if keylogfile and not sys.flags.ignore_environment:
            context.keylog_filename = keylogfile
    return context


def is_pyopenssl(ctx: "SSLContext"):
    if PyOpenSSLCtx:
        return isinstance(get_pyopenssl_ctx(ctx), PyOpenSSLCtx)
    else:
        return False


def get_pyopenssl_ctx(sslcontext: "SSLContext") -> "PyOpenSSLCtx|None":
    if hasattr(sslcontext, "pyopenssl"):
        return sslcontext.pyopenssl
    elif hasattr(sslcontext, "_ctx"):
        return sslcontext._ctx
