from x509creds import X509EncodedStore, load_der_certs, load_certs, Encoding, load_key_and_certificates, decode
from sslcontext.utils import _wincerts
from pathlib import Path



certs = bytearray()
count = 0
for cert, encoding, trust in _wincerts("ROOT"):
    # CA certs are never PKCS#7 encoded
    if encoding == "x509_asn":
        if trust is True:
            certs.extend(cert)
            count += 1
print(count)
bundle = Path(".private/ca-bundle.der")
bundle.write_bytes(bytes(certs))

test3 = list(decode(bundle.read_bytes(), Encoding.DER))


store = X509EncodedStore("./.private/store.pem")
store2 = X509EncodedStore("./.private/my-ca.pem")

data  = store.load_key_and_certificates()
data2  = store2.load_key_and_certificates()

pass