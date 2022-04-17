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
from certauth2.stores import ondiskPathStore

pemStore = ondiskPathStore("./.private/pem", encoding=Encoding.PEM)
derStore = ondiskPathStore("./.private/der", encoding=Encoding.DER)

store = None

ca = CertificateAuthority(
    ("./.private/my-ca.pem", "My Custom CA", None),
    cache=store,
)
cert, key, chain = ca["example.com"].to_pyopenssl()
pass
