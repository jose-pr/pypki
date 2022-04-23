from ._models import ProxyMap, Proxy


class SingleProxyMap(ProxyMap):
    def __init__(self, proxy:Proxy) -> None:
        self.proxy = proxy

    def __getitem__(self):
        return [self.proxy]