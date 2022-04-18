from sslcontext import PyOpenSSLContext, SSLContextProvider
from sslcontext.utils import load_default_certs
from . import SSLEngine, set_client_cert_engine
class EngineSSLContextProvider(SSLContextProvider):
    def __init__(self, engine:str, use_defaults:bool = True) -> None:
        self.use_defaults = use_defaults
        self.engine = SSLEngine(engine)
        pass

    def sslcontext(self, protocol):
        ctx = PyOpenSSLContext(protocol)
        set_client_cert_engine(ctx._ctx, self.engine)
        if self.use_defaults:
            load_default_certs(ctx)
        return ctx