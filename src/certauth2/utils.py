from datetime import datetime, timedelta
from enum import IntFlag
import ipaddress
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from x509creds import PrivateKey, Certificate

DEF_KEY_SIZE = 2048
CERT_MAX_AGE = timedelta(seconds=397 * 24 * 60 * 60)


def into_ip(ip: str):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def is_ip(ip: str):
    return into_ip(ip) is not None

   
try:
    import tld as _tld

except ImportError:
    _tld = None


def get_wildcard_domain(host: str, strict: bool = True):
    host_parts = host.split(".", 1)
    if len(host_parts) < 2 or (strict and not _tld):
        return host

    if strict:
        tld: "str|None" = _tld.get_tld(host, fix_protocol=True, fail_silently=True)

        # allow using parent domain if:
        # 1) no suffix (unknown tld)
        # 2) the parent domain is not the tld
        if not tld or tld != host_parts[1]:
            return host_parts[1]

        return host
    else:
        return host_parts[1]
