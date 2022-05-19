import sys, pathlib

import pytest

sys.path.insert(
    0, str(pathlib.Path(__file__).parent.parent.parent.joinpath("src").resolve())
)

from netproxy.config import Endpoint


@pytest.fixture(
    params=[
        {
            "proto": "https",
            "host": "google.com",
            "port": 443,
            "path": "/check_patch/asdsadsd/adssad",
        },
         {
            "proto": "https",
            "username": "user",
            "host": "google.com",
            "port": 443,
            "path": "/check_patch/asdsadsd/adssad",
        },
        {
            "proto": "https",
            "username": "user",
            'password': "pass",
            "host": "google.com",
            "port": 443,
            "path": "/check_patch/asdsadsd/adssad",
        },
        {
            "username": "user",
            "host": "google.com",
            "port": 443,
            "path": "/check_patch/asdsadsd/adssad",
        },

    ]
)
def endpoint_parts(request):
    return request.param


def test_endpoint(endpoint_parts: "dict"):
    parts = endpoint_parts
    netloc = parts["host"]
    if "port" in parts:
        netloc += ":" + str(parts["port"])
    if "password" in parts:
        userinfo = ":" + parts["password"]
    else:
        userinfo = ""
    if "username" in parts:
        userinfo = parts["username"] + userinfo

    autority = netloc
    if userinfo:
        autority = userinfo + "@" + autority
    if "proto" in parts:
        uri = parts["proto"] + "://"
    else:
        uri = ""

    uri += autority

    if "path" in parts:
        uri += parts["path"]

    for cfg in [uri, parts]:
        endpoint = Endpoint(cfg)
        assert endpoint.proto == parts.get("proto")
        assert endpoint.username == parts.get("username")
        assert endpoint.password == parts.get("password")
        assert endpoint.host == parts.get("host")
        assert endpoint.port == parts.get("port")
        assert endpoint.netloc == netloc
        assert endpoint.authority == autority
        assert endpoint.path == parts.get("path")
        assert endpoint.uri == uri

def test_getserv():
    for proto, port in [("https", 443), ("http", 80), ("ftp", 21), ("ssh", 22)]:
        assert (proto, port) == Endpoint(port=port).get_serv()
        assert (proto, port) == Endpoint(proto=proto).get_serv()

    



if __name__ == "__main__":
    test_endpoint()
