from typing import Callable
import importlib
from importlib import util as lib_util

from configparser import ConfigParser, SectionProxy
import re
paths = ["./.sslcontext.ini" ]
config:ConfigParser = ConfigParser()
config.read(paths)

class SslContextFactory:
    cls:Callable
    args:list
    kwargs:dict[str]

    def __init__(self, section:SectionProxy) -> None:
        self.kwargs = {}
        self.args = []
        try:
            import ssl
            for name, arg in section.items():
                match name:
                    case "context":
                        module, factory = ((arg or "").rsplit(".", maxsplit=1) + [None])[:2]
                        self.cls = getattr(importlib.import_module(module), factory)
                    case "args":
                        for arg in (arg or "").splitlines():
                            if arg.strip() != "":
                                self.args.append(eval(arg))
                    case kwarg if kwarg.startswith("arg_") and arg.strip("") != "":
                        self.kwargs[name.removeprefix("arg_")] = eval(arg)
        except Exception as e:
            self.cls = self.args = self.kwargs = None

    def context(self) -> object:
        if self.cls:
            return self.cls(*self.args, **self.kwargs)

SSL_CONTEXTS:dict[re.Pattern, SslContextFactory] = {}
for _key, section  in config.items():
    if _key == "DEFAULT":
        continue   
    SSL_CONTEXTS[re.compile(_key)] = SslContextFactory(section)

def inject_into_urllib3(urllib3: str = "urllib3"):
    if lib_util.find_spec(urllib3):
        connection = importlib.import_module(urllib3 + ".connection")
        if hasattr(connection, "_HTTPSConnection"):
            connection._HTTPSConnection = connection.HTTPSConnection
        class HTTPSConnection(connection.HTTPSConnection):
            def __init__(self, *w, **kw):
                ssl_contexts = kw.pop("ssl_contexts", None)
                if ssl_contexts == True or ssl_contexts is None:
                    ssl_contexts = SSL_CONTEXTS
                super().__init__(*w, **kw)
                if self.ssl_context is None and ssl_contexts:
                    try:                        
                        self.ssl_context = next(( factory.context() for match, factory in ssl_contexts.items() if match.match(self.host)), None)
                    except Exception as e:
                        print("Error")
                        pass

        connection.HTTPSConnection = HTTPSConnection

def extract_from_urllib3(urllib3: str = "urllib3"):
    if lib_util.find_spec(urllib3):
        connection = importlib.import_module(urllib3 + ".connection")
        if hasattr(connection, "_HTTPSConnection"):
            connection.HTTPSConnection = connection._HTTPSConnection

def inject_into(name:str):
    inject_into_urllib3(name)

def inject():
    for module in INJECT_INTO_MODULES:
        inject_into_urllib3(module)

INJECT_INTO_MODULES = ["urllib3", "pip._vendor.urllib3"]
