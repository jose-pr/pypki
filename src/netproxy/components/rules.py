from typing import TYPE_CHECKING, Literal

from ..config import Rule, ProxyRequest
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


class ProxyRule(Rule):
    type: Literal["proxy"] = "proxy"

    def generate_endpoint_for(rule, request: "ProxyRequest"):
        endpoint = super().generate_endpoint_for(request)
        endpoint.proto = (
            "tcp" if request.endpoint.proto == endpoint.proto else endpoint.proto
        )
        return endpoint


Rule.register(ProxyRule)


class WsgiRule(Rule):
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
