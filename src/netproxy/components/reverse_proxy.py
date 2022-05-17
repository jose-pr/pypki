from typing import TYPE_CHECKING
from twisted.web.proxy import ProxyClient, ProxyClientFactory
from twisted.web.resource import Resource
from twisted.web.http import Request
from twisted.web.server import NOT_DONE_YET
from twisted.internet import ssl
from twisted.protocols.tls import TLSMemoryBIOProtocol

if TYPE_CHECKING:
    from ..context import NetProxy
    from ..utils import Reactor


class CorsProxyClient(ProxyClient):
    def handleHeader(self, key: str, value):
        if key.lower().startswith(b"access-control-allow"):
            return
        return super().handleHeader(key, value)


class CorsProxyClientFactory(ProxyClientFactory):
    protocol = CorsProxyClient


class ReverseProxyResource(Resource):
    def __init__(
        self, host: str, port: int, ssl: ssl.ClientContextFactory, reactor: "Reactor"
    ):
        Resource.__init__(self)
        self.reactor = reactor
        self.host = host
        self.port = port
        self.ssl = ssl
        self.client_factory = ProxyClientFactory

    def getChild(self, path, request):
        return ReverseProxyResource(self.host, self.port, self.reactor)

    def render(self, request: Request):
        headers = request.getAllHeaders()

        headers[b"x-forwarded-host"] = headers.get(b"host", None)
        headers[b"host"] = self.host.encode("ascii")
        headers[b"x-forwarded-proto"] = (
            b"https" if isinstance(request.transport, TLSMemoryBIOProtocol) else b"http"
        )
        request.content.seek(0, 0)
        client_factory = self.client_factory(
            request.method,
            request.uri,
            request.clientproto,
            headers,
            request.content.read(),
            request,
        )
        if self.ssl:
            self.reactor.connectSSL(self.host, self.port, client_factory, self.ssl())
        else:
            self.reactor.connectTCP(self.host, self.port, client_factory)
        return NOT_DONE_YET
