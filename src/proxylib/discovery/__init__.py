import os
from .._models import ProxyMap as _Proxy
from ..pac import load_pac as _load_pac
from ..utils import SingleProxyMap as _Simple
from .common import EnvProxyConfig

if os.name == "nt":
    from .windows import system_proxy
else:
    def system_proxy() -> "_Proxy|str":
        return EnvProxyConfig.from_env()  


def auto_proxy(**urlopen_kwargs) -> _Proxy:
    proxy = system_proxy()
    if isinstance(proxy, str):
        return _load_pac(proxy, **urlopen_kwargs)
    else:
        return proxy
