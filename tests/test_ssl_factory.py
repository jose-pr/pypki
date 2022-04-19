import importpatch
from sslcontext_factory._extras import urllib3
urllib3.inject()
importpatch.inject()
import urllib3
http = urllib3.PoolManager()

response = http.request("GET", "https://www.google.com")
pass
