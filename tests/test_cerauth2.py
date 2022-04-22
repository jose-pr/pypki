import sys, pathlib

import pytest
sys.path.insert(0,str(pathlib.Path(__file__).parent.parent.joinpath("src").resolve()))

#import pytest
from certauth2.__main__ import main
from certauth2 import CertificateAuthority, Encoding
from certauth2.creds_store import ondiskPathStore, ondiskCredentialStore

from cryptography import x509


@pytest.fixture(params=[e for e in Encoding])
def encoding(request):
    return request.param

@pytest.fixture(params=["pem", "pfx", "pkcs12"])
def root_ca_suffix(request):
    return request.param

def get_ca(encoding:Encoding, root_ca_suffix:str ):
    store = ondiskCredentialStore(f"./.private/{encoding.name.lower()}", encoding=encoding)
    return CertificateAuthority(
        f"./.private/my-ca.{root_ca_suffix}",
        store=store,
    )


def test_root_certificate(encoding:Encoding, root_ca_suffix:str):
    ca = get_ca(encoding, root_ca_suffix)
    root_creds = ca.credentials
    assert root_creds.subject.rfc4514_string() == f"CN=my-ca"
    assert root_creds.cert.issuer == root_creds.subject
    usage:x509.Extension[x509.KeyUsage] = root_creds.cert.extensions.get_extension_for_oid(x509.OID_KEY_USAGE)
    assert usage.critical is True
    assert usage.value.crl_sign and usage.value.key_cert_sign
    assert root_creds.cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier == root_creds.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.key_identifier
    pass



def test_load_creds(encoding:Encoding):
    ca = get_ca(encoding, "pem")
    cert = ca.load_creds("example.com", overwrite=True)
    cp = ca["example.com"]
    assert cert.cert == cp.cert
    assert "example.com" in cert.cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    assert x509.OID_SERVER_AUTH in cert.cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert x509.OID_CLIENT_AUTH in cert.cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value


if __name__ == "__main__":
    test_root_certificate(Encoding.DER)
    test_load_creds()
