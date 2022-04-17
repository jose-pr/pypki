from interface import SSLContext, SSLSocket

try:
    from ssl import SSLContext as NativeSSLContext, _SSLMethod

    SSLContext.register(NativeSSLContext)
except:
    pass
try:
    from _vendor.pyopenssl import PyOpenSSLContext, is_pyopenssl, PyOpenSSLSocket
except:
    ...


class SSLContextProvider:
    def sslcontext(protocol: "_SSLMethod") -> SSLContext:
        errs = []
        try:
            from ssl import SSLContext
        except BaseException as e:
            errs.append(e)
            SSLContext = None
        if SSLContext is None:
            try:
                from ._vendor.pyopenssl import PyOpenSSLContext as SSLContext
            except BaseException as e:
                errs.append(e)
                pass
        if SSLContext:
            return SSLContext(protocol=protocol)
        else:
            raise Exception("Could not load a module that provides a SSLContext", errs)
