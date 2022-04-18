from importlib import import_module as _import

from configparser import ConfigParser
import re
from sslcontext import SSLContextProvider
from sslcontext.utils import set_sslcontext_defaults
class DefaultSSLContextProvider(SSLContextProvider):
    def sslcontext(self, protocol):
        ctx = super().sslcontext(protocol)
        set_sslcontext_defaults(ctx)        
        return ctx

DEFAULT_SSL_CONTEXT_PROVIDER:SSLContextProvider = DefaultSSLContextProvider()
SSL_CONTEXT_PROVIDERS: 'dict[re.Pattern, SSLContextProvider]' = {}
SSL_CONTEXT_PROVIDERS_LOAD_ERRORS: 'dict[str, Exception]' = {}

paths = ["./.sslcontext.ini"]
config: ConfigParser = ConfigParser()
config.read(paths)


for _key, section in config.items():
    args = []
    kwargs = {}
    try:
        for name, arg in section.items():
            if name == "context":
                module, factory = ((arg or "").rsplit(".", maxsplit=1) + [None])[:2]
                factory = getattr(_import(module), factory)
            elif name == "args":
                for arg in (arg or "").splitlines():
                    if arg.strip() != "":
                        args.append(eval(arg))
            elif name.startswith("arg_") and arg.strip("") != "":
                kwargs[name[len("arg_") :]] = eval(arg)
        provider:SSLContextProvider = factory(*args, **kwargs)
    except Exception as e:
        SSL_CONTEXT_PROVIDERS_LOAD_ERRORS[_key] = e
        continue

    if _key == "DEFAULT":
        DEFAULT_SSL_CONTEXT_PROVIDER = provider
    else:
        SSL_CONTEXT_PROVIDERS[re.compile(_key)] = provider

def ssl_context_provider_for(target:str = None):
    if target:
        for pattern, provider in SSL_CONTEXT_PROVIDERS.items():
            if pattern.match(target):
                return provider
    return DEFAULT_SSL_CONTEXT_PROVIDER