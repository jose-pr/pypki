from interface import SSLContext, WrappedSocket, SSLContextProvider
try:
    from ssl import SSLContext as NativeSSLContext
    SSLContext.register(NativeSSLContext)
except:
    pass
try:
    from urllib3.contrib.pyopenssl import PyOpenSSLContext
    SSLContext.register(PyOpenSSLContext)
except:
    ...


