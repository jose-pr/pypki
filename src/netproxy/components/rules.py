from typing import TYPE_CHECKING, Literal

from ..config import Endpoint, Rule, ProxyRequest
from ..utils import TLS_PROTOCOLS

if TYPE_CHECKING:
    from ..context import NetProxy


class DirectRule(Rule):
    type: Literal["direct"] = "direct"

    def generate_endpoint_for(rule, request: "ProxyRequest"):
        endpoint = super().generate_endpoint_for(request)
        endpoint.proto = "tcp"
        return endpoint


Rule.register(DirectRule)


class _ReverseProxyRule(Rule):
    def generate_endpoint_for(rule, request: "ProxyRequest"):
        endpoint = super().generate_endpoint_for(request)
        key = (rule.type, request.endpoint, Endpoint(endpoint))
        reverse_proxy = request.context.reverse_proxies.use(key)
        request.on_finish.addBoth(lambda _: request.context.reverse_proxies.done(key))
        endpoint.host = request.context.interface
        endpoint.port = reverse_proxy._realPortNumber
        return endpoint

class ProxyRule(_ReverseProxyRule):
    type: Literal["proxy"] = "proxy"

    def generate_endpoint_for(rule, request: "ProxyRequest"):
        endpoint = super().generate_endpoint_for(request)
        endpoint.proto = (
            "tcp" if request.endpoint.proto == endpoint.proto else endpoint.proto
        )
        return endpoint


Rule.register(ProxyRule)


class WsgiRule(_ReverseProxyRule):
    type: Literal["wsgi"] = "wsgi"

    def generate_endpoint_for(rule, request: "ProxyRequest"):
        endpoint = super().generate_endpoint_for(request)
        endpoint.proto = (
            "tcp"
            if request.endpoint.proto in TLS_PROTOCOLS
            and endpoint.proto in TLS_PROTOCOLS
            else endpoint.proto
        )
        return endpoint


Rule.register(WsgiRule)
