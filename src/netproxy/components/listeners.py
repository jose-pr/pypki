from typing import TYPE_CHECKING, Literal

from netproxy.models.config import ListenCfg

from ..models import StructLike
from ..config import Endpoint, Listener
from .http_proxy import HttpProxyFactory

if TYPE_CHECKING:
    from ..context import NetProxy


class HttpProxyListener(Listener):
    type: Literal["http_proxy"] = "http_proxy"

    def _create_factory(self, context: "NetProxy"):
        return HttpProxyFactory(context)


Listener.register(HttpProxyListener)


class WsgiListener(Listener):
    type: Literal["wsgi"] = "wsgi"
    app: str

    def _create_factory(self, context: "NetProxy"):
        return context.wsgi[self.app]


Listener.register(WsgiListener)


class ReverseProxy(Listener):
    type: Literal["reverse_proxy"] = "reverse_proxy"
    target: Endpoint

    @classmethod
    def _normalize_src(cls, src: "ListenCfg") -> StructLike:
        return {
            **src,
            "interface": Endpoint(src.get("interface", {})),
            "target": Endpoint(src.get("target", {})),
        }

    def _create_factory(self, context: "NetProxy"):
        return context.sites.use(self)


Listener.register(ReverseProxy)
