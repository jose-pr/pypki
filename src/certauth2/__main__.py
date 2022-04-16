# =================================================================
from argparse import ArgumentParser
from pathlib import Path
from certauth2.cache import FileCache
from x509creds import X509Credentials
from . import CERTS_DIR
from . import CertificateAuthority


def main(args=None):
    parser = ArgumentParser(description="Certificate Authority Cert Maker Tools")

    parser.add_argument("issuer", help="Path to existing CA or for a new root CA file")

    parser.add_argument(
        "-c",
        "--issuername",
        action="store",
        help="Name for issuer CA certificate",
    )

    parser.add_argument(
        "--issuerpass",
        action="store",
        help="Issuer cert file password",
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
        "-S",
        "--sans",
        action="store",
        default="",
        help="add Subject Alternate Name to the cert",
    )

    r = parser.parse_args(args=args)

    certs_dir: str = r.certs_dir
    issuer = Path(r.issuer)
    issuername: str = r.issuername
    issuerpass: str = r.issuerpass
    hostname: str = r.hostname
    sans: "list[str]" = r.sans.split(",")
    overwrite: bool = r.force if not hostname else False

    if overwrite and issuer.exists():
        issuer.unlink()

    ca = CertificateAuthority(
        (str(issuer), issuername, issuerpass),
        cache=certs_dir,
    )

    # Just creating the root cert
    if not hostname:
        if ca._root_creds_new:
            print(f'Created new root cert: "{issuer}"')
            return 0
        else:
            print(f'Issuer cert "{issuer}" already exists, use -f to overwrite')
            return 1

    # Sign a certificate for a given host
    overwrite = r.force
    ca.load_cert(
        hostname,
        overwrite=overwrite,
        sans=sans,
    )
    cache: FileCache[str, X509Credentials, X509Credentials] = ca.cache
    if cache.modified:
        print(f'Created new cert "{ hostname }" signed by {issuer}')
        return 0

    else:
        print(f'Cert for "{ hostname }" already exists, use -f to overwrite')
        return 1


if __name__ == "__main__":  # pragma: no cover
    main()
