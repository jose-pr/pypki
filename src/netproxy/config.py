from typing import TYPE_CHECKING, NamedTuple
from typing_extensions import TypeAlias as _Alias
from urllib.parse import ParseResultBytes
import socket as _socket
from importlib import import_module as _import
import json as _json


from .models.config import *
from .models import *
from .utils import TLS_PROTOCOLS, as_str, Logger
from ._re import _URI_REGEX

if TYPE_CHECKING:
    EndpointSrc: _Alias = "StructLike|str|ParseResultBytes"
    from .context import NetProxy
    from twisted.internet.protocol import ClientFactory, ServerFactory
    from twisted.internet.defer import Deferred
    from twisted.internet.ssl import ClientContextFactory, ContextFactory


class Endpoint(FactoryClass):
    __TYPE_PROP__ = "type"
    proto: str
    username: "str|None"
    password: "str|None"
    host: str
    port: "int|None"
    path: "str|None"

    @classmethod
    def _normalize_src(cls, src: "EndpointSrc|Endpoint") -> StructLike:
        if isinstance(src, (str, bytes)):
            src = as_str(src)
            proto, username, password, host, port, path = _URI_REGEX.match(src).groups()
            cfg: EndpointCfg = {
                "proto": proto,
                "username": username,
                "password": password,
                "host": host,
                "port": port,
                "path": path,
            }
        elif isinstance(src, ParseResultBytes):
            cfg: EndpointCfg = {
                "proto": src.scheme.decode("ascii"),
                "username": src.username.decode("ascii") if src.username else None,
                "password": src.password.decode("ascii") if src.password else None,
                "host": src.hostname.decode("ascii"),
                "port": src.port,
                "path": src.path.decode("ascii") if src.path else None,
            }
        elif isinstance(src, Endpoint):
            cfg: EndpointCfg = {
                "proto": src.proto,
                "username": src.username,
                "password": src.password,
                "host": src.host,
                "port": src.port,
                "path": src.path,
            }
        else:
            cfg: EndpointCfg = {
                "proto": None,
                "username": None,
                "password": None,
                "host": None,
                "port": None,
                "path": None,
                **src,
            }
        port = cfg["port"]
        if isinstance(port, str):
            cfg["port"] = int(port)
        return cfg

    @property
    def netloc(self):
        host = self.host or ""
        port = f":{self.port}" if self.port else ""
        return f"{host}{port}"

    @property
    def userinfo(self):
        password = f":{self.password}" if self.password else ""
        return f"{self.username if self.username else ''}{password}"

    @property
    def authority(self):
        userinfo = self.userinfo
        userinfo = f"{userinfo}@" if userinfo else ""
        return f"{userinfo}{self.netloc}"

    @property
    def target(self):
        proto = f"{self.proto}://" if self.proto else ""
        return proto + self.netloc

    @property
    def uri(self):
        proto = f"{self.proto}://" if self.proto else ""
        path = f"/{self.path}" if self.path else ""
        return f"{proto}{self.authority}{path}"

    def __repr__(self) -> str:
        if hasattr(self, "__TYPE_PROP__"):
            t = getattr(self, self.__TYPE_PROP__, "")
        else:
            t = ""
        if t:
            t = t + " "
        return f"{t}{self.uri}"

    def __hash__(self) -> int:
        return hash(str(self))

    def get_serv(self):
        port = self.port
        proto = self.proto

        if not proto:
            if port:
                try:
                    proto = _socket.getservbyport(port)
                except:
                    raise ValueError(
                        f"Protocol not provided and cannot find it from the supplied port: {port}"
                    )
            else:
                raise ValueError(
                    f"No protocol provided and no port to get default from."
                )
        elif not port:
            try:
                port = _socket.getservbyname(proto)
            except:
                raise ValueError(
                    f"Port not provided and cannot find it from the supplied protocol: {proto}"
                )

        return proto, port

    def connect(
        self,
        context: "NetProxy",
        client: "ClientFactory",
        sslcontext: "ClientContextFactory" = None,
    ):
        proto, port = self.get_serv()
        if proto in TLS_PROTOCOLS:
            return context.reactor.connectSSL(
                self.host,
                port,
                factory=client,
                contextFactory=sslcontext or context.default_client_ssl_context_factory,
            )
        else:
            return context.reactor.connectTCP(self.host, port, factory=client)

    def listen(
        self,
        context: "NetProxy",
        server: "ServerFactory",
        sslcontext: "ContextFactory" = None,
    ):
        if self.proto in TLS_PROTOCOLS:
            return context.reactor.listenSSL(
                self.port or 0,
                server,
                sslcontext or context.ca[self.host],
                interface=self.host,
            )

        else:

            return context.reactor.listenTCP(
                self.port or 0, server, interface=self.host
            )


class ProxyRequest(NamedTuple):
    endpoint: Endpoint
    on_finish: "Deferred"
    context: "NetProxy"

    def resolve(self, factory: "ClientFactory"):
        target = self.endpoint.target
        for pattern, rule in self.context.rules:
            if pattern.match(target):
                endpoint = rule.generate_endpoint_for(self)
                endpoint.connect(self.context, factory)
                return
        raise ValueError(target)


class ProxyEndpoint(Endpoint):
    rule: "Rule"


class Listener(FactoryClass):
    type: str = None
    interface: Endpoint
    __TYPE_PROP__ = "type"

    def __repr__(self) -> str:
        t = getattr(self, self.__TYPE_PROP__, "__UNK__")
        return f"{t} at {self.interface}"

    @classmethod
    def _get_type(cls, src: StructLike) -> str:
        return super()._get_type(src).lower()

    @classmethod
    def _normalize_src(cls, src: "ListenCfg|str") -> StructLike:
        if isinstance(src, str):
            type, endpoint = src.strip().split(" ", maxsplit=1)
            return {"type": type, "interface": Endpoint(endpoint or {})}
        return {**src, "interface": Endpoint(src.get("interface", {}))}

    def _logger(self, context: "NetProxy"):
        return Logger(
            f"{context.logger.namespace}.listeners.{self.type}",
            observer=context.logger.observer,
        )

    def _create_factory(self, context: "NetProxy"):
        self._logger(context).warn(
            f"Ignoring proxy listener due to unknown type: {self.type}"
        )

    def start_listening(self, context: "NetProxy"):
        factory = self._create_factory(context)
        logger = self._logger(context)
        if not factory:
            logger.warn(f"Cant start proxy listener due to no factory: {self}")
            return
        self.interface.listen(context, factory)


class Rule(FactoryClass):
    __TYPE_PROP__ = "type"
    type: str = None
    endpoint: Endpoint

    @classmethod
    def _get_type(cls, src: StructLike) -> str:
        return super()._get_type(src).lower()

    @classmethod
    def _normalize_src(cls, src: "RuleCfg|str") -> StructLike:
        if isinstance(src, str):
            type, endpoint, *_ = src.strip().split(" ", maxsplit=1) + [None]
            return {"type": type, "endpoint": Endpoint(endpoint or {})}
        return {**src, "endpoint": Endpoint(src.get("endpoint", {}))}

    def generate_endpoint_for(rule, request: "ProxyRequest"):
        return ProxyEndpoint(
            rule=rule,
            proto=rule.endpoint.proto or request.endpoint.proto,
            host=rule.endpoint.host or request.endpoint.host,
            port=rule.endpoint.port or request.endpoint.port,
        )

    def __repr__(self) -> str:
        t = getattr(self, "__TYPE_PROP__", None)
        if not t:
            t = "__UNK__"
        return f"{t} {self.endpoint}"


class FunctionDeclaration(FactoryClass):
    name: str
    args: "list[ObjectLike]"
    kwds: "dict[str, ObjectLike]"

    @classmethod
    def _normalize_src(cls, src: FunctionCfg) -> StructLike:
        return {
            "name": src["name"],
            "args": src.get("args", []),
            "kwds": src.get("kwds", {}),
        }

    def __call__(self):
        module, method = (self.name.rsplit(".", maxsplit=1) + [None])[:2]
        module = _import(module)
        method = getattr(module, method) if method else module
        return method(*self.args, **self.kwds)

    def __repr__(self) -> str:
        args: "list[str]" = []
        for arg in self.args:
            args.append(_json.dumps(arg))
        for name, val in self.kwds.items():
            args.append(f"{name}={_json.dumps(val)}")

        return f'{self.name}({", ".join(args)})'
