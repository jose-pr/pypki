try:
    import tld as _tld

except ImportError:
    _tld = None

from x509creds.utils import into_ip

def is_ip(ip:str):
    return into_ip(ip) is not None

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