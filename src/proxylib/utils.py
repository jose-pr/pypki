from typing import TYPE_CHECKING, Sequence, TypedDict as _Dict
from socket import AddressFamily as _A
from ._models import ProxyMap, Proxy
from .pac import load_pac

class SingleProxyMap(ProxyMap):
    def __init__(self, proxy: 'Proxy|Sequence[Proxy]' = None) -> None:
        self.proxies:Sequence[Proxy] = proxy if isinstance(proxy, Sequence) else (proxy,)

    def __getitem__(self):
        return self.proxies


try:
    import netifaces

    if TYPE_CHECKING:
        from netifaces import INETAddress

    def get_addresses():
        ints: "list[INETAddress]" = []
        for i in netifaces.interfaces():
            addrs = netifaces.interfaces(i)
            ints.extend(addrs.get(_A.AF_INET, []))
        return ints

except ImportError:

    def get_addresses():
        return []

def get_proxymap_for(src: "str|Proxy|None") -> ProxyMap:
    if isinstance(src, str):
        proxy = Proxy.from_uri(src)
        netloc = proxy.netloc

        if (
            proxy.scheme in ["http", "https"]
            and not src.endswith(netloc)
            or src.endswith(netloc + "/")
        ):
            return load_pac(src)
    else:
        proxy = src

    return SingleProxyMap(proxy)
