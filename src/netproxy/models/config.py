from typing import Literal as _Lit, TypedDict as _TypedDict
from ._utils import ObjectLike


class EndpointCfg(_TypedDict):
    proto: str
    address: str
    port: str


class ListenCfg(EndpointCfg):
    type: str


class WsgiListenCfg(ListenCfg):
    type: _Lit["wsgi"]
    app: str


class FunctionCfg(_TypedDict):
    name: str
    args: "list[ObjectLike]"
    kwds: "dict[str, ObjectLike]"


class WsgiAppCfg(FunctionCfg):
    pass


class RuleCfg(_TypedDict):
    type: str
    endpoint: "EndpointCfg|str"


class NetProxyCfg(_TypedDict):
    home_dir: "str|None"
    private_interface: "str|None"
    pac: "str|None"
    wsgi: "dict[str, WsgiAppCfg]"
    rules: "dict[str, RuleCfg]"
