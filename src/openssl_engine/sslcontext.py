from sslcontext import PyOpenSSLContext, SSLContextProvider, SSLContext
from sslcontext.utils import get_pyopenssl_ctx
from . import SSLEngine, set_client_cert_engine


class EngineSSLContextProvider(SSLContextProvider):
    def __init__(self, engine: str, use_defaults: bool = True) -> None:
        self.use_defaults = use_defaults
        self.engine = SSLEngine(engine)
        pass

    def sslcontext(self, protocol):
        ctx = PyOpenSSLContext(protocol)
        set_client_cert_engine(ctx._ctx, self.engine)
        if self.use_defaults:
           ctx.load_default_certs()
        return ctx

    def apply_to_context(self, context: SSLContext):
        ctx = get_pyopenssl_ctx(context)
        if ctx:
            set_client_cert_engine(ctx._ctx, self.engine)
        else:
            raise ValueError(
                "SSLContext must have a method called pyopenssl that returns a OpenSSL.SSL.Context object"
            )
