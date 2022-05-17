from typing import TYPE_CHECKING, Literal

from ..config import Listener
from .http_proxy import HttpProxyFactory

if TYPE_CHECKING:
    from ..context import NetProxy


class HttpProxyListener(Listener):
    type:Literal['http_proxy'] = "http_proxy"
    def _create_factory(self, context: "NetProxy"):
        return HttpProxyFactory(context)

Listener.register(HttpProxyListener)

class WsgiListener(Listener):
    type:Literal['wsgi'] = 'wsgi'
    app:str
    def _create_factory(self, context: "NetProxy"):
        return context.wsgi[self.app]

Listener.register(WsgiListener)