from .models import SSLContextMap, SSLContext


class NoSSLContextMap(SSLContextMap):
    def __geitem__(self, uri: str):
        return None
