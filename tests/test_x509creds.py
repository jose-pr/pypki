from x509creds import X509EncodedStore, load_der_certs, load_certs, Encoding, load_key_and_certificates, decode
from pathlib import Path



test3 = list(decode(bundle.read_bytes(), Encoding.DER))


store = X509EncodedStore("./.private/store.pem")
store2 = X509EncodedStore("./.private/my-ca.pem")

data  = store.load_key_and_certificates()
data2  = store2.load_key_and_certificates()

pass