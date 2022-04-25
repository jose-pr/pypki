from typing import (
    Iterable as _Iter,
    Literal as _Literal,
    get_args as _args,
    cast as _cast,
    overload as _overload,
)
import socket as _socket
import ipaddress as _ip
from fnmatch import fnmatch as _shexpmatch
import datetime as _datetime
from urllib.request import urlopen as _urlopen
from warnings import warn as _warn
from ._models import ProxyMap, Proxy
from ._re import _PAC_REGEX, _URI_REGEX


_WEEKDAY = _Literal["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
_WEEKDAYS = ("SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT")


class PAC(ProxyMap):

    #### UTILITY FUNCTIONS ####
    @staticmethod
    def dnsResolve(host: str, /):
        try:
            return _socket.gethostbyname(host)
        except:
            return

    @staticmethod
    def myIpAddress():
        return _socket.gethostbyname(_socket.gethostname())

    @staticmethod
    def dnsDomainLevels(host: str, /):
        return len(host.split("."))

    @staticmethod
    def convert_addr(ipaddr: str, /):
        return int(_ip.ip_address(ipaddr))

    @staticmethod
    def shExpMatch(test: str, shexp: str, /):
        return _shexpmatch(test, shexp)

    #### TIME FUNCTIONS ####
    @_overload
    def weekdayRange(wd1: _WEEKDAY, gmt: 'None|_Literal["GMT"]' = None, /):
        ...

    @_overload
    def weekdayRange(
        wd1: _WEEKDAY, wd2: _WEEKDAY, gmt: 'None|_Literal["GMT"]' = None, /
    ):
        ...

    @staticmethod
    def weekdayRange(wd1: _WEEKDAY, /, *args: '_WEEKDAY|_Literal["GMT"]'):
        start = _WEEKDAYS.index(wd1.upper())
        if args:
            wd2 = args[0].upper()
            if len(args) == 2:
                gmt = args[1].upper() == "GMT"
                end = _WEEKDAYS[wd2]
            elif wd2 == "GMT":
                gmt = True
                end = start
            else:
                end = _WEEKDAYS[wd2]

        else:
            end = start

        today = (
            _datetime.datetime.utcnow() if gmt else _datetime.datetime.now()
        ).isoweekday()
        if today == 7:
            today = 0
        return start <= today <= end

    @staticmethod
    def dateRange(*args):
        return False

    @staticmethod
    def timeRange(*args):
        return False

    #### HOSTNAME FUNCTIONS ####

    @staticmethod
    def isPlainHostname(host: str):
        return "." not in host

    @staticmethod
    def dnsDomainIs(host: str, domain: str):
        return host.endswith(domain)

    @staticmethod
    def localHostOrDomainIs(host: str, hostdom: str):
        return "." not in host and hostdom.startswith(host) or hostdom == host

    @staticmethod
    def isResolvable(host: str):
        try:
            _socket.gethostbyname(host)
            return True
        except:
            return False

    @staticmethod
    def isInNet(host: str, pattern: str, mask: str):
        try:
            ip = _ip.IPv4Address(host)
        except:
            try:
                ip = _ip.IPv4Address(PAC.dnsResolve(host))
            except:
                return False
        net = _ip.IPv4Network(f"{pattern}/{mask}", strict=False)
        return ip in net

    @staticmethod
    def FindProxyForURL(url: str, host: str, /) -> str:
        return "DIRECT"

    def __getitem__(self, url: str) -> _Iter[Proxy]:
        parsed = _URI_REGEX.match(url)
        if not parsed:
            raise ValueError(url)
        scheme, user, p, host, port = parsed.groups()
        pac_proxies = self.FindProxyForURL(
            f"{scheme}://{host}{f':{port}' if port else ''}", host
        )
        return (Proxy(*proxy) for proxy in _PAC_REGEX.findall(pac_proxies))


try:
    from ._jscontext import JSContext as _JSContext

    class JSProxyAutoConfig(PAC, _JSContext):
        ...

    _jspac = True
except ImportError:

    _jspac = False


def load_pac(url: str, **urllib_kwds):
    if "://" not in url:
        url = ("file://" if url.startswith("/") else "https://") + url
    with _urlopen(url, **urllib_kwds) as resp:
        js = resp.read()
    if "FindProxyForURL" not in js:
        raise Exception("Not FindProxyForURL found int response from: " + url)
    if not _jspac:
        _warn(f"Can not load js from: {url} as pac. Install libproxy[jspac]")
        return PAC()
    else:
        return JSProxyAutoConfig(js)
