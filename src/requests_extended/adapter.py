import base64
from urllib.parse import unquote
from typing import Mapping
from requests import PreparedRequest, Response, Request

from sslcontext import SSLContext
from requests.adapters import HTTPAdapter, Retry
from urllib3 import HTTPConnectionPool, PoolManager, ProxyManager
from urllib3.exceptions import ProxyError, ConnectionError
from requests.exceptions import ProxyError, InvalidProxyURL, ConnectionError
from requests.utils import select_proxy, prepend_scheme_if_needed
from proxylib import ProxyMap, Proxy
from proxylib.utils import SingleProxyMap
from .models import SSLContextMap
from .utils import NoSSLContextMap

try:
    from urllib3.contrib.socks import SOCKSProxyManager
except ImportError:

    class SOCKSProxyManager:
        def __init__(self, *args, **kwargs) -> None:
            raise ProxyError("Missing package for SOCKS proxy")


class _RequestsProxyMap(ProxyMap):
    def __init__(self, proxies: "dict[str,str|None]") -> None:
        self.proxies = proxies

    def __getitem__(self, uri: str):
        return Proxy.from_uris(select_proxy(uri))


class HTTPAdapterExtended(HTTPAdapter):
    poolmanager: PoolManager
    proxy_manager: "dict[Proxy, ProxyManager]"

    def __init__(
        self,
        pool_connections: int = ...,
        pool_maxsize: int = ...,
        max_retries: "Retry | int | None" = ...,
        pool_block: bool = ...,
        sslcontexts: "SSLContextMap" = None,
        proxies: ProxyMap = None,
    ) -> None:
        self.sslcontexts = sslcontexts or NoSSLContextMap()
        self.proxies = proxies or SingleProxyMap()
        super().__init__(pool_connections, pool_maxsize, max_retries, pool_block)

    def proxy_headers(self, proxy: Proxy):
        if proxy.username:
            unquote(proxy.username)
            auth = base64.b64encode(
                unquote(proxy.username) + ":" + unquote(proxy.password)
            )
            return {"Proxy-Authorization": f"Basic {auth}"}
        else:
            return {}

    def proxy_manager_for(self, proxy: Proxy, **proxy_kwargs) -> ProxyManager:
        if proxy in self.proxy_manager:
            manager = self.proxy_manager[proxy]
        elif proxy.scheme.startswith("socks"):
            manager = self.proxy_manager[proxy] = SOCKSProxyManager(
                proxy.url,
                username=proxy.username,
                password=proxy.password,
                num_pools=self._pool_connections,
                maxsize=self._pool_maxsize,
                block=self._pool_block,
                **proxy_kwargs,
            )
        else:
            manager = self.proxy_manager[proxy] = ProxyManager(
                proxy.url,
                headers=self.proxy_headers(proxy),
                num_pools=self._pool_connections,
                maxsize=self._pool_maxsize,
                block=self._pool_block,
                **proxy_kwargs,
            )
        return manager

    def send(
        self,
        request: PreparedRequest,
        stream: bool = ...,
        timeout: "None | float | tuple[float, float] | tuple[float, None]" = ...,
        verify: "bool | str" = ...,
        cert: "None | bytes | str | tuple[bytes | str, bytes | str]" = ...,
        proxies: "Mapping[str, str] | ProxyMap | None | str" = ...,
    ) -> Response:
        if isinstance(proxies, ProxyMap):
            pass
        elif isinstance(proxies, dict):
            proxies = _RequestsProxyMap(proxies)
        elif isinstance(proxies, str):
            proxies = SingleProxyMap(Proxy.from_uris(proxies))
        elif proxies is False:
            proxies = SingleProxyMap()
        elif not proxies:
            proxies = self.proxies

        return super().send(request, stream, timeout, verify, cert, proxies)

    def request_url(self, request: Request, proxies: ProxyMap):
        proxy: Proxy = next(proxies[request.url], None)
        return super().request_url(request, {"all": proxy.url} if proxy else {})

    def get_connection(self, url, proxies: ProxyMap = ...):
        # Shouldnt be needed
        # url = prepend_scheme_if_needed(url, "http")
        errs = []
        for proxy in proxies[url] or [None]:
            if proxy:
                if not proxy.netloc:
                    raise InvalidProxyURL("")
                try:
                    manager = self.proxy_manager_for(proxy)
                    return manager.connection_from_url(url)
                except ProxyError as e:
                    errs.append(e)
            else:
                try:
                    return self.poolmanager.connection_from_url(url)
                except ConnectionError as e:
                    errs.append(e)
        err = errs[0] if len(errs) == 1 else ConnectionError(errs)
        raise err

    def cert_verify(
        self,
        conn: HTTPConnectionPool,
        url: str,
        verify: "SSLContext|None|bool|str",
        cert: "tuple|str",
    ):
        if verify is True:
            # Shouldnt be needed
            # url = prepend_scheme_if_needed(url, "http")
            if url.startswith("https://"):
                ctx = self.sslcontexts[url]
                if ctx is None:
                    verify = True

        if verify and isinstance(verify, SSLContext):
            if cert:
                if isinstance(cert, tuple):
                    verify.load_cert_chain(*cert)
                else:
                    verify.load_cert_chain(cert)
            conn.conn_kw["ssl_context"] = verify
        else:
            return super().cert_verify(conn, url, verify, cert)
