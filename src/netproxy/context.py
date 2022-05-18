from typing import IO, TYPE_CHECKING
from typing_extensions import TypeAlias as _Alias
from re import Pattern as _Pattern
import re
from twisted.web.server import Site
from twisted.web.wsgi import WSGIResource
from twisted.internet.ssl import ClientContextFactory as _DefaultSSLContextFactory
from certauth2 import CertificateAuthority, onMemoryCredentialStore
from pathlib import Path

from .utils import CachedFactory, Logger, creds_into_twisted_options
from .config import *
from .constants import DEFAULT_PROXY_PATH

if TYPE_CHECKING:
    from .utils import Reactor
    from twisted.internet.tcp import Port as _Port
    from twisted.logger import ILogObserver as _Observer

_RevProxyKey: _Alias = "tuple[str, Endpoint, Endpoint]"


class NetProxy:
    logger: Logger
    reactor: "Reactor"
    listeners: "list[Listener]"
    rules: "list[tuple[_Pattern, Rule]]"
    wsgi: "dict[str, Site]"
    ca: "CertificateAuthority"
    _config: NetProxyCfg
    sites: CachedFactory["NetProxy", Endpoint, Site]
    reverse_proxies: CachedFactory["NetProxy", "_RevProxyKey", "_Port"]
    vendor: "dict[str]"
    default_client_ssl_context_factory: _DefaultSSLContextFactory
    home_dir: Path

    def __init__(
        self,
        reactor: "Reactor" = None,
        home: str = None,
        config: "str|NetProxyCfg" = None,
        log: Logger = None,
    ) -> None:
        self.reactor = reactor
        if self.reactor is None:
            from twisted.internet import reactor as _reactor

            self.reactor = _reactor
        self.home_dir = Path(home) if home else None
        self._initlog(log)
        if not config or isinstance(config, (str, Path)):
            self._load(
                config or self.home_dir or DEFAULT_PROXY_PATH.joinpath("config.toml")
            )
        else:
            self._config = config
        _logfile = self._config.get("logfile", None)
        if _logfile and not log:
            self._initlog(_logfile)
        elif log is None:
            self._initlog(True)
        self.init()

    def _initlog(self, log: "Logger|_Observer|Path|str|bool"):
        if isinstance(log, Logger):
            self.logger = log
        else:
            if not hasattr(self, "logger"):
                self.logger = Logger("NetProxy")
            from twisted.logger import textFileLogObserver, globalLogBeginner

            try:

                if log is True:
                    import sys

                    log = sys.stdout

                if isinstance(log, (str, Path)):
                    observer = textFileLogObserver(Path(log).open("w"))
                elif isinstance(log, IO) or hasattr(log, "write"):
                    observer = textFileLogObserver(log)
                else:
                    observer = log

                if observer:
                    self.logger.observer.addObserver(observer)
                    globalLogBeginner.beginLoggingTo(
                        [observer], redirectStandardIO=False
                    )

            except Exception as e:
                self.logger.error("Could not start logger")

    def _load(self, path: "Path|str"):
        path = Path(path).resolve()
        try:
            self.logger.info(f"Loading config from: {path}")
            if path.exists():
                import tomli

                with path.open("rb") as config:
                    self._config = tomli.load(config)
                if self.home_dir is None:
                    home = self._config.get("home_dir", None)
                    if not home or home == "./":
                        self._config["home_dir"] = str(path.parent)

            else:
                self._config = {}
        except Exception as e:
            self.logger.critical(f"Could not load config from path: {path}")
            raise e

    def init(self):
        config = self._config
        logger = self.logger
        if not self.home_dir:
            self.home_dir = Path(config.get("home_dir", DEFAULT_PROXY_PATH)).resolve()
        logger.info(f"Home directory is {self.home_dir}")
        self.home_dir.mkdir(exist_ok=True, parents=True)
        self.default_client_ssl_context_factory = FunctionDeclaration(
            config.setdefault(
                "ssl_context",
                {
                    "name": _DefaultSSLContextFactory.__module__
                    + "."
                    + _DefaultSSLContextFactory.__qualname__
                },
            )
        )()
        self.rules = []
        for pattern, rule in config.setdefault("rules", {}).items():
            regex, rule = re.compile(pattern), Rule(rule)
            logger.info(
                "Found rule:<{rule}> with pattern: {pattern}",
                rule=rule,
                pattern=pattern,
            )
            self.rules.append((regex, rule))
        interface = config.setdefault("private_interface", "127.0.0.1")
        logger.info("Listening <{interface}> internally", interface=interface)
        pac = config.setdefault("pac", "proxy.pac")
        logger.info("Using <{pac}> for proxy auto configuration", pac=pac)
        from .components.reverse_proxy import ReverseProxyResource

        def generate_site(context: NetProxy, key: Endpoint):
            return Site(ReverseProxyResource(Endpoint(key), context))

        def generate_reverse_proxy(context: NetProxy, key: "_RevProxyKey"):
            type, at, target = key
            site = (
                context.wsgi[target.host]
                if type == "wsgi"
                else context.sites.use(target)
            )
            return Endpoint(proto=at.proto, host=context.interface, port=0).listen(
                context, site, context.ca[at.host]
            )

        def remove_reverse_proxy(
            context: NetProxy, proxy: "_Port", key: "_RevProxyKey"
        ):
            type, at, target = key
            if type != "wsgi":
                context.sites.done(target)
            proxy.stopListening()

        self.reverse_proxies = CachedFactory(
            self, generate_reverse_proxy, remove_reverse_proxy, 10
        )
        self.sites = CachedFactory(self, generate_site, size_hint=10)
        self.listeners = []
        for listen in config.setdefault("listen", []):
            listener = Listener(listen)
            logger.info("Found listener config: {listener}", listener=listener)
            self.listeners.append(listener)

        self.wsgi = {}
        for name, conf in config.setdefault("wsgi", {}).items():
            wsgiFn = FunctionDeclaration(conf)
            logger.info(f"Create wsgi app: {name} with: {wsgiFn}")
            self.wsgi[name] = Site(
                WSGIResource(self.reactor, self.reactor.getThreadPool(), wsgiFn())
            )

        ca_creds = self.resolve_path(config.setdefault("ca", "ca.p12"))
        logger.info(f"CA credentials from :{ca_creds}")
        ca_store = onMemoryCredentialStore(100, creds_into_twisted_options)
        self.ca = CertificateAuthority(
            ca_creds, ca_store, verify_tld=False, domain_cert=True
        )
        logger.info("Done with init")

    def listen(self):
        for listen in self.listeners:
            self.logger.info(f"Starting listening {listen}")
            try:
                listen.start_listening(self)
            except Exception as e:
                self.logger.error(
                    "Failed to start {listen} due to {e}", listen=listen, e=e
                )

    def resolve_path(self, path: "str|Path"):
        return (self.home_dir / path).resolve()

    def pac_file(self):
        return self.resolve_path(self._config["pac"])

    @property
    def interface(self) -> str:
        return self._config["private_interface"]
