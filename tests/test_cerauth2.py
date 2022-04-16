from certauth2.__main__ import main

"""
    certs_dir: str = r.certs_dir
    issuer: str = r.issuer
    issuername: str = r.issuername or None
    issuerpass: str = r.issuerpass or None
    hostname: str = r.hostname
    sans: "list[str]" = r.sans.split(",")
    overwrite: bool = r.force if not hostname else False
"""
main(["--certs-dir", "./.private/ca_certs", "./.private/ca.pem", "--hostname", "example.com", "-f", "--sans", "172.19.1.1,*.example.com"])
