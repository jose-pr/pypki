from ipaddress import IPv4Address, IPv6Address
import os

from io import BytesIO

from argparse import ArgumentParser

from collections import OrderedDict

import threading
from typing import Iterable, Literal
from pathlib import Path
from cryptography.hazmat.primitives.hashes import HashAlgorithm, SHA256
from .utils import cert_builder, into_ip
from x509creds import X509Credentials, Encoding, x509

# =================================================================
# Valid for 3 years from now
# Max validity is 39 months:
# https://casecurity.org/2015/02/19/ssl-certificate-validity-periods-limited-to-39-months-starting-in-april/
CERT_NOT_AFTER = 3 * 365 * 24 * 60 * 60

CERTS_DIR = "./ca/certs/"

CERT_NAME = "certauth sample CA"

DEF_HASH_FUNC = SHA256()

DEF_ENCODING = Encoding.PEM

ROOT_CA = "!!root_ca"


# =================================================================
class CertificateAuthority(object):
    """
    Utility class for signing individual certificate
    with a root cert.

    Static generate_ca_root() method for creating the root cert

    All certs saved on filesystem. Individual certs are stored
    in specified certs_dir and reused if previously created.
    """
    credentials:X509Credentials
    def __init__(
        self,
        credentials: "X509Credentials|str|tuple[str,str|None]",
        cert_cache=None,
        cert_not_before=0,
        cert_not_after=CERT_NOT_AFTER,
        encoding: "Literal[Encoding.PEM,Encoding.PKCS12]|None" = None,
        password: str = None,
        hash: "HashAlgorithm|None" = None,
    ):
        self.hash = hash or DEF_HASH_FUNC
        self.encoding = encoding or DEF_ENCODING
        self.cert_not_before = cert_not_before
        self.cert_not_after = cert_not_after

        if isinstance(credentials, str):
            credentials = (credentials, None)
        if isinstance(credentials[0], str):
            path = Path(credentials[0])
            try:
                encoding = Encoding.from_suffix(path.suffix)
            except:
                encoding = self.encoding

            if path.exists():
                credentials = X509Credentials.load(
                    cert=(path.read_bytes(), encoding), password=credentials[1]
                )
            else:
                builder, key = self._cert_builder(path.stem, True)
                cert = builder.sign(key, self.hash)
                credentials = X509Credentials(cert, key)
                path.write_bytes(credentials.dump(encoding, password))
        self.credentials = credentials
        if isinstance(cert_cache, str):
            self.cert_cache = FileCache(cert_cache)
        elif isinstance(cert_cache, int):
            self.cert_cache = LRUCache(max_size=cert_cache)
        elif cert_cache is None:
            self.cert_cache = LRUCache(max_size=100)
        else:
            self.cert_cache = cert_cache

    def load_cert(
        self,
        host: str,
        overwrite: bool = False,
        include_cache_key: bool = False,
        sans: "Iterable[str|IPv6Address|IPv4Address]|None" = None,
    ):

        sans = sans or []

        creds: X509Credentials = None

        if not overwrite:
            creds = self.cert_cache.get(host)

        if not creds:
            # if not cached, generate new root or host cert
            creds = self.generate_host_cert(
                host,
                sans=sans,
            )
            # store cert in cache
            self.cert_cache[host] = creds

        if not include_cache_key:
            return creds

        else:
            cache_key = host
            if hasattr(self.cert_cache, "key_for_host"):
                cache_key = self.cert_cache.key_for_host(host)

            return creds, cache_key

    def cert_for_host(
        self,
        host,
        overwrite=False,
        sans: "Iterable[str|IPv6Address|IPv4Address]|None" = None,
    ):

        res = self.load_cert(
            host,
            overwrite=overwrite,
            wildcard_use_parent=False,
            include_cache_key=True,
            sans=sans,
        )

        return res[1]

    def _cert_builder(self, certname, root=False):
        builder, key = cert_builder(certname, issuer=None if root else self.creds.cert)
        builder.not_valid_before(self.cert_not_before)
        builder.not_valid_before(self.cert_not_after)
        return builder, key

    def generate_host_cert(
        self,
        host,
        sans: "Iterable[str|IPv6Address|IPv4Address]|None" = None,
    ):

        builder, key = self._cert_builder(host)
        _done = []
        _sans = []
        for san in [host, *sans]:
            ip = into_ip(san)
            san = str(san)
            if san not in _done:
                if ip:
                    _sans.append(x509.IPAddress(ip))
                _sans.append(x509.DNSName(san))
                _done.append(san)

        builder = builder.add_extension(x509.SubjectAlternativeName(_sans), False) 
        cert = builder.sign(self.credentials.key, self.hash)
        return X509Credentials(cert, key)


# =================================================================
class FileCache(object):
    def __init__(self, certs_dir):
        self._lock = threading.Lock()
        self.certs_dir = certs_dir
        self.modified = False

        if self.certs_dir and not os.path.exists(self.certs_dir):
            os.makedirs(self.certs_dir)

    def key_for_host(self, host):
        host = host.replace(":", "-")
        return os.path.join(self.certs_dir, host) + ".pem"

    def __setitem__(self, host, cert_string):
        filename = self.key_for_host(host)
        with self._lock:
            with open(filename, "wb") as fh:
                fh.write(cert_string)
                self.modified = True

    def get(self, host):
        filename = self.key_for_host(host)
        try:
            with open(filename, "rb") as fh:
                return fh.read()
        except:
            return b""


# =================================================================
class RootCACache(FileCache):
    def __init__(self, ca_file):
        self.ca_file = ca_file
        ca_dir = os.path.dirname(ca_file) or "."
        super(RootCACache, self).__init__(ca_dir)

    def key_for_host(self, host=None):
        return self.ca_file


# =================================================================
class LRUCache(OrderedDict):
    def __init__(self, max_size):
        super(LRUCache, self).__init__()
        self.max_size = max_size

    def __setitem__(self, host, cert_string):
        super(LRUCache, self).__setitem__(host, cert_string)
        if len(self) > self.max_size:
            self.popitem(last=False)


# =================================================================
def main(args=None):
    parser = ArgumentParser(description="Certificate Authority Cert Maker Tools")

    parser.add_argument("root_ca_cert", help="Path to existing or new root CA file")

    parser.add_argument(
        "-c",
        "--certname",
        action="store",
        default=CERT_NAME,
        help="Name for root certificate",
    )

    parser.add_argument("-n", "--hostname", help="Hostname certificate to create")

    parser.add_argument(
        "-d", "--certs-dir", default=CERTS_DIR, help="Directory for host certificates"
    )

    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite certificates if they already exist",
    )

    parser.add_argument(
        "-w",
        "--wildcard_cert",
        action="store_true",
        help="add wildcard SAN to host: *.<host>, <host>",
    )

    parser.add_argument(
        "-I", "--cert_ips", action="store", default="", help="add IPs to the cert's SAN"
    )

    parser.add_argument(
        "-D",
        "--cert_fqdns",
        action="store",
        default="",
        help="add more domains to the cert's SAN",
    )

    r = parser.parse_args(args=args)

    certs_dir = r.certs_dir
    wildcard = r.wildcard_cert

    root_cert = r.root_ca_cert
    hostname = r.hostname

    if r.cert_ips != "":
        cert_ips = r.cert_ips.split(",")
    else:
        cert_ips = []
    if r.cert_fqdns != "":
        cert_fqdns = r.cert_fqdns.split(",")
    else:
        cert_fqdns = []

    if not hostname:
        overwrite = r.force
    else:
        overwrite = False

    cert_cache = FileCache(certs_dir)
    ca_file_cache = RootCACache(root_cert)

    ca = CertificateAuthority(
        ca_name=r.certname,
        ca_file_cache=ca_file_cache,
        cert_cache=cert_cache,
        overwrite=overwrite,
    )

    # Just creating the root cert
    if not hostname:
        if ca_file_cache.modified:
            print('Created new root cert: "' + root_cert + '"')
            return 0
        else:
            print(
                'Root cert "' + root_cert + '" already exists,' + " use -f to overwrite"
            )
            return 1

    # Sign a certificate for a given host
    overwrite = r.force
    ca.load_cert(
        hostname,
        overwrite=overwrite,
        wildcard=wildcard,
        wildcard_use_parent=False,
        cert_ips=cert_ips,
        cert_fqdns=cert_fqdns,
    )

    if cert_cache.modified:
        print('Created new cert "' + hostname + '" signed by root cert ' + root_cert)
        return 0

    else:
        print('Cert for "' + hostname + '" already exists,' + " use -f to overwrite")
        return 1


if __name__ == "__main__":  # pragma: no cover
    main()
