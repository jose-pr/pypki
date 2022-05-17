import sys, pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.parent.joinpath("src").resolve()))

from netproxy.config import Endpoint

def test_endpoint():
    endpoint = Endpoint("http://google.com:443/check_patch/asdsadsd/adssad")
    assert endpoint.username == None
    assert endpoint.host == "google.com"
    assert endpoint.authority == "google.com:443"
    assert endpoint.proto == "http"
    assert endpoint.port == 443
    assert endpoint.path == "/check_patch/asdsadsd/adssad"
    ...


if __name__ == "__main__":
    test_endpoint()