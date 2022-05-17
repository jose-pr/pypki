from twisted.internet import ssl
from OpenSSL import SSL

try:
    from openssl_engine import SSLEngine, set_client_cert_engine

    class CapiSSLContextFactory(ssl.ClientContextFactory):
        def getContext(self):
            ctx = self._contextFactory(self.method)
            set_client_cert_engine(ctx, SSLEngine("capi"))
            ctx.set_options(SSL.OP_NO_SSLv2)
            return ctx

except ImportError:
    pass

