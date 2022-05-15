from typing import TYPE_CHECKING
from re import Pattern as _Pattern
from twisted.web.server import Site
from certauth2 import CertificateAuthority

from .utils import CachedFactory, Logger
from .config import *

if TYPE_CHECKING:
    from .utils import Reactor
    from twisted.internet import tcp as _tcp


class NetProxy:
    logger: Logger
    reactor: "Reactor"
    listeners: 'list[Listener]'
    rules: 'list[tuple[_Pattern, Rule]]'
    wsgi: 'dict[str, Site]'
    ca: 'CertificateAuthority'
    _config: NetProxyCfg
    sites : CachedFactory['NetProxy', Endpoint, Site]
    reverse_proxies: CachedFactory['NetProxy', 'tuple[str, Endpoint, Endpoint]', '_tcp.Port']
    vendor: 'dict[str]'

    ssl_context_factory:...
    ...
