try:
    from OpenSSL import crypto as _crypto, SSL as _SSL
    from OpenSSL.crypto import _lib, _ffi, _new_mem_buf

    try:
        from sslcontext.utils import is_pyopenssl, get_pyopenssl_ctx
    except:
        def get_pyopenssl_ctx(ctx) -> '_SSL.Context|None' :
            ctx = getattr(ctx, "_ctx", None)
            return ctx if isinstance(ctx, _SSL.Context) else None
            
        def is_pyopenssl(ctx):
            if hasattr(ctx, "_ctx") and isinstance(ctx._ctx, _SSL.Context):
                return True
            else:
                return False

except ImportError as e:
    _crypto = None

    def is_pyopenssl(ctx):
        return False
    
    def get_pyopenssl_ctx(ctx):
        return None

    from cryptography.hazmat.bindings.openssl.binding import Binding as _binding

    _binding = _binding()
    _ffi = _binding.ffi
    _lib = _binding.lib

    def _new_mem_buf(buffer=None):
        # Code from Openssl.crypto
        if buffer is None:
            bio = _lib.BIO_new(_lib.BIO_s_mem())
            free = _lib.BIO_free
        else:
            data = _ffi.new("char[]", buffer)
            bio = _lib.BIO_new_mem_buf(data, len(buffer))

            def free(bio, ref=data):
                return _lib.BIO_free(bio)

        if bio == _ffi.NULL:
            raise Exception("Something wrong")
        bio = _ffi.gc(bio, free)
        return bio
