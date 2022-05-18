from typing import TYPE_CHECKING
from twisted.web.proxy import ProxyClientFactory
from twisted.web.resource import Resource
from twisted.web.http import Request
from twisted.web.server import NOT_DONE_YET
from twisted.protocols.tls import TLSMemoryBIOProtocol

from netproxy.config import Endpoint

if TYPE_CHECKING:
    from ..context import NetProxy

class ReverseProxyResource(Resource):
    def __init__(self, target: Endpoint, netproxy: "NetProxy"):
        Resource.__init__(self)
        self.netproxy = netproxy
        self.target = target
        self.client_factory = ProxyClientFactory

    def getChild(self, path, request):
        return ReverseProxyResource(self.target, self.netproxy)

    def render(self, request: Request):
        headers = request.getAllHeaders()

        headers[b"x-forwarded-host"] = headers.get(b"host", None)
        headers[b"host"] = self.target.host.encode("ascii")
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
        self.target.connect(self.netproxy, client_factory)
        return NOT_DONE_YET
