import ssl
from typing import Callable, cast
from OpenSSL import crypto

import importlib
from importlib import util as lib_util

from platformdirs import importlib

from openssl_engine import set_client_cert_engine

from . import DISPLAY_FORMAT, CAPIEngine

TRUSTED_STORES = ["ROOT", "CA"]
DEFAULT_SSL_OPTIONS = (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2)

def get_capi_store_certs(storename: str):
    with CAPIEngine() as capi:
        return [
            crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            for cert in capi.list_certs(storename, DISPLAY_FORMAT.PEM)
        ]


def get_windows_store_certs(storename: str):
    return [
        (crypto.load_certificate(crypto.FILETYPE_ASN1, cert), trust)
        for cert, encoding, trust in ssl.enum_certificates(storename)
    ]


def trusted_certs(
    stores: list[str] | None = None,
    filter: Callable[[crypto.X509, bool], bool] = lambda cert, trusted: trusted,
):
    certs = list[crypto.X509]()
    for store in stores if stores is not None else TRUSTED_STORES:
        for cert, trusted in get_windows_store_certs(store):
            if filter(cert, trusted):
                certs.append(cert)
    return certs


class WindowsSSLContext:
    pass


def declareContext(urllib3: str = "urllib3"):
    if lib_util.find_spec(urllib3):

        pyopenssl = importlib.import_module(urllib3 + ".contrib.pyopenssl")
        urllib3_util = importlib.import_module(urllib3 + ".util")
        ssl_context = pyopenssl.PyOpenSSLContext

        if not hasattr(urllib3_util, "WindowsSSLContext"):

            class WindowsSSLContext(ssl_context):
                def __init__(
                    self,
                    protocol=ssl.PROTOCOL_TLS_CLIENT,
                    options: ssl.Options | None = None,
                    trusted_stores: list[str] = None,
                ):
                    super().__init__(protocol)

                    if options is not None:
                        self.options = options
                    elif DEFAULT_SSL_OPTIONS is not None:
                        self.options = DEFAULT_SSL_OPTIONS

                    store = self._ctx.get_cert_store()
                    for cert in trusted_certs(trusted_stores):
                        store.add_cert(cert)
                    self._capi = CAPIEngine()
                    set_client_cert_engine(self._ctx, self._capi)

                def __del__(self):
                    self._capi.free()

            urllib3_util.WindowsSSLContext = WindowsSSLContext
        return urllib3_util.WindowsSSLContext


def _set_urllib3_sslcontext(context, urllib3):
    util = importlib.import_module(urllib3 + ".util")
    util.SSLContext = context
    util.ssl_.SSLContext = context


def inject_into_urllib3(urllib3: str = "urllib3"):
    if lib_util.find_spec(urllib3):
        util = importlib.import_module(urllib3 + ".util")
        prev = util.ssl_.SSLContext
        pyopenssl = importlib.import_module(urllib3 + ".contrib.pyopenssl")
        pyopenssl.inject_into_urllib3()
        if util.IS_PYOPENSSL:
            context = declareContext(urllib3)
            _set_urllib3_sslcontext(context, urllib3)
        return prev


def extract_from_urllib3(context: ssl.SSLContext, urllib3: str = "urllib3"):
    pyopenssl = importlib.import_module(urllib3 + ".contrib.pyopenssl")
    pyopenssl.extract_from_urllib3()
    if context:
        _set_urllib3_sslcontext(context, urllib3)

def inject_into(name:str):
    inject_into_urllib3(name)

def inject():
    inject_into_urllib3("urllib3")
    inject_into_urllib3("pip._vendor.urllib3")


WindowsSSLContext = declareContext()
