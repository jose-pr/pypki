import os
import requests
from urllib3.util.ssl_ import DEFAULT_CIPHERS, OP_NO_COMPRESSION, OP_NO_SSLv2, OP_NO_SSLv3, OP_NO_TICKET, CERT_REQUIRED
from proxylib.discovery import auto_proxy
from sslcontext import SSLContext, PROTOCOL_TLS_CLIENT

from .adapter import HTTPAdapterExtended
from .models import SSLContextMap

def set_urllib3_default_context(ctx:SSLContext):
    ctx.set_ciphers(DEFAULT_CIPHERS)
    ctx.options = OP_NO_SSLv2 | OP_NO_SSLv3 | OP_NO_COMPRESSION | OP_NO_TICKET
    ctx.verify_mode = CERT_REQUIRED
    if hasattr(ctx, "post_handshake_auth"):
        ctx.post_handshake_auth = True
    if hasattr(ctx, "check_hostname"):
        ctx.check_hostname = False

    if hasattr(ctx, "keylog_filename"):
        sslkeylogfile = os.environ.get("SSLKEYLOGFILE", None)
        if sslkeylogfile:
            ctx.keylog_filename = sslkeylogfile

class SystemSSLContextMap(SSLContextMap):
    def __init__(self) -> None:
        try: 
            from openssl_engine.sslcontext import EngineSSLContextProvider
            self.default = EngineSSLContextProvider.sslcontext(PROTOCOL_TLS_CLIENT)
            set_urllib3_default_context(self.default)
        except ImportError:
            self.default = None
    def __getitem__(self, uri: str) -> 'SSLContext|None|bool|str':
        return self.default

def create_system_session():
    session = requests.Session()
    sslmap = SystemSSLContextMap()
    adapter = HTTPAdapterExtended(sslcontexts=sslmap, proxies=auto_proxy())
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session