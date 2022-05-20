from .models import SSLContextMap, SSLContext


class NoSSLContextMap(SSLContextMap):
    def __getitem__(self, uri: str):
        return None
