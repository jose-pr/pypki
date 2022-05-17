from typing import TYPE_CHECKING, AnyStr
from twisted.web.http import Request, HTTPFactory
from twisted.web.proxy import Proxy, ProxyClientFactory
from twisted.internet.protocol import Protocol, ClientFactory
from urllib.parse import urlparse
from pathlib import Path

from ..config import ProxyRequest, Endpoint
from ..utils import as_bytes

if TYPE_CHECKING:
    from ..context import NetProxy


class ConnectProxyRequest(Request):
    channel: "ConnectProxy"

    @property
    def netproxy(self):
        return self.channel.factory.netproxy

    def process(self):
        uri = urlparse((b"https://" + self.uri) if b"://" not in self.uri else self.uri)
        if not uri.hostname:
            self._local_file(
                self.netproxy.pac_file, "application/x-ns-proxy-autoconfig"
            )
            return
        try:
            request = ProxyRequest(
                endpoint=Endpoint(uri),
                context=self.netproxy,
                on_finish=self.notifyFinish(),
            )
        except Exception as e:
            self.reply(f"Host {self.uri} is not supported by this proxy", code=502)
            return

        if self.method == b"CONNECT":
            clientFactory = ConnectProxyClientFactory(self)
        else:
            headers = self.getAllHeaders().copy()
            headers[b"host"] = as_bytes(request.endpoint.netloc)
            self.content.seek(0, 0)
            clientFactory = ProxyClientFactory(
                self.method,
                uri.path + (b"?" + uri.query if uri.query else b""),
                self.clientproto,
                headers,
                self.content.read(),
                self,
            )
        try:
            request.resolve(clientFactory)
        except ValueError as e:
            endpoint: Endpoint = e.args[0]
            self.reply(f"Host {endpoint.uri} is not supported by this proxy", code=503)

    def reply(
        self,
        body: AnyStr = "",
        code=200,
        message: AnyStr = "Ok",
        mimetype: str = "text/html",
    ):
        self.setResponseCode(code, as_bytes(message))
        self.responseHeaders.addRawHeader("Content-Type", mimetype)
        if body is not None:
            self.write(as_bytes(body))
        self.finish()

    def _local_file(self, path: str, mimetype: str = "text/html"):
        path: Path = Path(path)
        if path.exists():
            self.reply(body=path.read_bytes(), mimetype=mimetype)
        else:
            self.reply(code=400, messsage="Not Found")


class ConnectProxy(Proxy):
    factory: "HttpProxyFactory"
    requestFactory: ConnectProxyRequest
    connectedRemote: "ConntectProxyClient|None"


class ConntectProxyClient(Protocol):
    connectedClient: ConnectProxy
    factory: "ConnectProxyClientFactory"


class ConnectProxyClientFactory(ClientFactory):
    protocol = ConntectProxyClient
    request: ConnectProxyRequest

    def __init__(self, request: ConnectProxyRequest) -> None:
        self.request = request

    def clientConnectionFailed(self, connector, reason):
        self.request.reply(message="Gateway Error", body=str(reason), code=501)


class HttpProxyFactory(HTTPFactory):
    netproxy: "NetProxy"
    protocol = ConnectProxy

    def __init__(
        self,
        netproxy: "NetProxy",
        logPath=None,
        timeout=...,
        logFormatter=None,
        reactor=None,
    ):
        self.netproxy = netproxy
        super().__init__(logPath, timeout, logFormatter, reactor)

    def logPrefix(self):
        return self.netproxy.logger.namespace + ".proxies.http_proxy"
