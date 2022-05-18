from typing import TYPE_CHECKING, AnyStr
from requests import request
from twisted.web.http import Request, HTTPFactory, _REQUEST_TIMEOUT
from twisted.web.proxy import Proxy, ProxyClientFactory
from twisted.internet.protocol import Protocol, ClientFactory
from urllib.parse import urlparse
from pathlib import Path

from ..config import ProxyRequest, Endpoint
from ..utils import as_bytes

if TYPE_CHECKING:
    from ..context import NetProxy


class HttpProxyRequest(Request):
    channel: "HttpProxy"

    @property
    def netproxy(self):
        return self.channel.factory.netproxy

    def process(self):
        uri = urlparse((b"https://" + self.uri) if b"://" not in self.uri else self.uri)
        if not uri.hostname:
            self.reply(self.netproxy.pac_file, "application/x-ns-proxy-autoconfig")
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
        body: "AnyStr|Path" = "",
        code=200,
        message: AnyStr = None,
        mimetype: str = "text/html",
    ):
        if isinstance(body, Path):
            if body.exists():
                body = body.read_bytes()
            else:
                code = 400
                message = "Not Found"
        elif body is not None:
            body = as_bytes(body)

        if message is None and 200 <= code < 300:
            message = b"Ok"
        else:
            message = as_bytes(message or "")

        self.setResponseCode(code, message)
        self.responseHeaders.addRawHeader("Content-Type", mimetype)
        if body is not None:
            self.write(body)
        self.finish()


class HttpProxy(Proxy):
    factory: "HttpProxyFactory"
    requestFactory: HttpProxyRequest = HttpProxyRequest
    connectedRemote: "ConntectProxyClient|None" = None

    def requestDone(self, request: HttpProxyRequest):
        if request.method == b"CONNECT" and self.connectedRemote is not None:
            self.connectedRemote.connectedClient = self
            self._handlingRequest = False
            self._networkProducer.resumeProducing()
            if self._savedTimeOut:
                self.setTimeout(self._savedTimeOut)
            data = b"".join(self._dataBuffer)
            self._dataBuffer = []
            self.setLineMode(data)
        else:
            super().requestDone(request)

    def connectionLost(self, reason):
        if self.connectedRemote is not None:
            self.connectedRemote.transport.loseConnection()
        else:
            super().connectionLost(reason)

    def dataReceived(self, data):
        if self.connectedRemote is not None:
            self.connectedRemote.transport.write(data)
        else:
            return super().dataReceived(data)


class ConntectProxyClient(Protocol):
    connectedClient: HttpProxy
    factory: "ConnectProxyClientFactory"

    def connectionMade(self):
        request = self.factory.request
        request.channel.connectedRemote = self
        request.setResponseCode(200, b"CONNECT OK")
        request.setHeader("Content-Length", "0")
        request.finish()

    def connectionLost(self, reason=...):
        if self.connectedClient is not None:
            self.connectedClient.transport.loseConnection()

    def dataReceived(self, data: bytes):
        if self.connectedClient is not None:
            self.connectedClient.transport.write(data)
        else:
            self.factory.request.netproxy.logger.error("Unexpected data received")


class ConnectProxyClientFactory(ClientFactory):
    protocol = ConntectProxyClient
    request: HttpProxyRequest

    def __init__(self, request: HttpProxyRequest) -> None:
        self.request = request

    def clientConnectionFailed(self, connector, reason):
        self.request.reply(message="Gateway Error", body=str(reason), code=501)


class HttpProxyFactory(HTTPFactory):
    netproxy: "NetProxy"
    protocol = HttpProxy

    def __init__(
        self,
        netproxy: "NetProxy",
        logPath=None,
        timeout=_REQUEST_TIMEOUT,
        logFormatter=None,
        reactor=None,
    ):
        self.netproxy = netproxy
        super().__init__(logPath, timeout, logFormatter, reactor)

    def logPrefix(self):
        return self.netproxy.logger.namespace + ".proxies.http_proxy"
