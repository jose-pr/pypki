from .interface import SSLContext, SSLSocket, SSLContextProvider
from ._vendor.ssl import *
try:
    from ssl import SSLContext as NativeSSLContext, _SSLMethod

    SSLContext.register(NativeSSLContext)
except:
    pass
try:
    from _vendor.pyopenssl import PyOpenSSLContext, is_pyopenssl, PyOpenSSLSocket
except:
    ...


