from importlib import util as _util, import_module as _import
from types import ModuleType
from typing import Iterable
from sslcontext import PROTOCOL_TLS_CLIENT
from ..factory import ssl_context_provider_for

INJECT_INTO_MODULES = ["urllib3", "pip._vendor.urllib3"]


def patch_urllib3(urllib3: str = "urllib3"):
    if _util.find_spec(urllib3):
        connection = _import(urllib3 + ".connection")
        if hasattr(connection, "_HTTPSConnection"):
            connection._HTTPSConnection = connection.HTTPSConnection

        class HTTPSConnection(connection.HTTPSConnection):
            def __init__(self, *w, **kw):
                ssl_provider = kw.pop("ssl_context_provider", None)
                super().__init__(*w, **kw)
                if self.ssl_context is None and ssl_provider:
                    try:
                        if ssl_provider == True or ssl_provider is None:
                            ssl_provider = ssl_context_provider_for(self.host)
                        self.ssl_context = ssl_provider.sslcontext(PROTOCOL_TLS_CLIENT)
                    except Exception as e:
                        pass

        connection.HTTPSConnection = HTTPSConnection


def unpatch_urllib3(urllib3: str = "urllib3"):
    if _util.find_spec(urllib3):
        connection = _import(urllib3 + ".connection")
        if hasattr(connection, "_HTTPSConnection"):
            connection.HTTPSConnection = connection._HTTPSConnection


def patch(module: ModuleType):
    patch_urllib3(module.__name__)


def inject(modules: Iterable[str] = INJECT_INTO_MODULES):
    import importpatch

    for module in modules:
        importpatch.add(module, __name__)
