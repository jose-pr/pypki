import os
import requests
from urllib3.util.ssl_ import DEFAULT_CIPHERS, OP_NO_COMPRESSION, OP_NO_SSLv2, OP_NO_SSLv3, OP_NO_TICKET, CERT_REQUIRED
from proxylib.discovery import auto_proxy
from sslcontext import SSLContext

from .adapter import HTTPAdapterExtended

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


def create_system_session():
    session = requests.Session()
    sslmap = None #TODO
    adapter = HTTPAdapterExtended(sslcontexts=sslmap, proxies=auto_proxy())
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session