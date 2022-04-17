from x509creds import X509EncodedStore



store = X509EncodedStore("./.private/store.pem")
store2 = X509EncodedStore("./.private/my-ca.pem")

data  = store.load_key_and_certificates()
data2  = store2.load_key_and_certificates()

pass