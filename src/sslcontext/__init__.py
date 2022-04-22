from .interface import SSLContext, SSLSocket, SSLContextProvider
from ._vendor.ssl import *

try:
    from ssl import SSLContext as NativeSSLContext, _SSLMethod
    NativeSSLContext.pyopenssl = lambda : None
    SSLContext.register(NativeSSLContext)
except ImportError:
    pass
try:
    from ._vendor.pyopenssl import PyOpenSSLContext, PyOpenSSLSocket
except ImportError as e:
    ...
