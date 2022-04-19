try:
    from ssl import SSLContext
except ImportError:
     SSLContext = None
try:
    from OpenSSL.SSL import Context as PyOpenSSLCtx
except ImportError:
    PyOpenSSLCtx = None