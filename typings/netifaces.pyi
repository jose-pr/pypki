from typing import Literal, TypedDict as _Dict, overload
import socket as _socket

class INETAddress(_Dict):
    addr: str
    netmask: str
    broadcast: str

class LinkPeerIFace(_Dict):
    addr: str
    netmask: str
    peer: str

class LinkMACIFace(_Dict):
    addr: str

@overload
def interfaces() -> list[str]: ...
@overload
def interfaces(
    iface: str,
) -> dict[_socket.AddressFamily, INETAddress | LinkPeerIFace | LinkMACIFace]: ...
@overload
def gateways() -> dict[
    _socket.AddressFamily, tuple[str, str, bool]
] | dict[Literal["default"], tuple[str, str]]: ...
