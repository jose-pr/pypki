import os
from typing import Iterable as _Iter
import re
from .._models import Proxy, ProxyMap, URL
from ..pac import load_pac, PAC
from ..utils import SingleProxyMap, get_proxymap_for, get_addresses


class EnvProxyConfig(ProxyMap):
    __slots__ = ("http_proxy", "https_proxy", "no_proxy")

    def __init__(
        self,
        http_proxy: "str|Proxy|None",
        https_proxy: "str|Proxy|None",
        no_proxy: "_Iter[str]",
    ) -> None:
        self.http_proxy = get_proxymap_for(http_proxy)
        self.https_proxy = get_proxymap_for(https_proxy)
        self.no_proxy = (
            [
                re.compile(re.escape(_no) + ".*") if _no != "<local>" else None
                for _no in set(no_proxy)
            ]
            if no_proxy
            else []
        )

    def __getitem__(self, url: str) -> _Iter[Proxy]:
        uri = URL.from_str(url)
        url = f"{uri.scheme}://{uri.netloc}"
        for _no in self.no_proxy:
            if _no is None:
                for addr in get_addresses():
                    if PAC.isInNet(url, addr["addr"], addr["netmask"]):
                        return [None]
            else:
                if _no.match(url):
                    return [None]
        return self.https_proxy[url] if uri.scheme == "https" else self.http_proxy[url]

    @staticmethod
    def from_env():
        https = os.environ.get("HTTPS_PROXY", None)
        if not https:
            https = os.environ.get("https_proxy")

        http = os.environ.get("HTTP_PROXY", None)
        if not http:
            http = os.environ.get("http_proxy")

        no_proxy = os.environ.get("NO_PROXY", None)
        if not no_proxy:
            no_proxy = os.environ.get("no_proxy")

        return EnvProxyConfig(http, https, no_proxy)
