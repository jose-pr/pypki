from x509creds import load_store, get_bytes_and_encoding



data, encoding = get_bytes_and_encoding("./.private/store.pem")

store = load_store(data, encoding)

pass