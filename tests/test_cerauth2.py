from certauth2.__main__ import main

"""
    certs_dir: str = r.certs_dir
    issuer: str = r.issuer
    issuername: str = r.issuername or None
    issuerpass: str = r.issuerpass or None
    hostname: str = r.hostname
    sans: "list[str]" = r.sans.split(",")
    overwrite: bool = r.force if not hostname else False

main(
    [
        "--certs-dir",
        "./.private/ca_certs",
        "./.private/my-ca.pem",
        "--hostname",
        "example.com",
        "-f",
        "--issuername",
        "My Custom CA",
        "--sans",
        "172.19.1.1,*.example.com",
    ]
)"""
from certauth2 import CertificateAuthority, Encoding
from certauth2.stores import ondiskCredentialStore

derStore = ondiskCredentialStore("./.private/der", encoding=Encoding.DER)


ca = CertificateAuthority(
    ("./.private/my-ca.pem", "My Custom CA", None),
    cache=derStore,
)
cert, key, chain = ca.load_creds("example.com", overwrite=True)
pass

