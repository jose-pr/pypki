import sys, pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent.joinpath("src").resolve()))
from proxylib.pac import PAC, JSProxyAutoConfig
from proxylib._jscontext import JSContext


def test_pac_domain_levels():
    assert PAC.dnsDomainLevels("104.16.41.2") == 4


def test_pac_convert_addr():
    assert PAC.convert_addr("104.16.41.2") == 1745889538


def test_pac_dnsdomainis():
    assert PAC.dnsDomainIs("www.mozilla.org", ".mozilla.org") == True
    assert PAC.dnsDomainIs("www", ".mozilla.org") == False


def test_pac_localHostOrDomainIs():
    assert (
        PAC.localHostOrDomainIs("www.mozilla.org", "www.mozilla.org") == True
    ), "exact match"
    assert (
        PAC.localHostOrDomainIs("www", "www.mozilla.org") == True
    ), "hostname match, domain not specified"
    assert (
        PAC.localHostOrDomainIs("www.google.com", "www.mozilla.org") == False
    ), "(domain name mismatch)"
    assert (
        PAC.localHostOrDomainIs("home.mozilla.org", "www.mozilla.org") == False
    ), "(hostname mismatch)"


def test_pac_isInNet():
    assert PAC.isInNet("10.8.12.10", "10.8.12.1", "255.255.255.0") == True
    assert PAC.isInNet("10.8.12.10", "10.8.13.1", "255.255.255.0") == False
    assert PAC.isInNet("10.8.12.10", "10.0.0.0", "255.0.0.0") == True


def test_jscontext():
    class TestContext(JSContext):
        _test = "a"

        @staticmethod
        def test(test):
            return "test" + test

        def test2(self):
            return self._test

    ctx = TestContext("")
    assert ctx.test("s") == "tests"
    assert ctx.test2() == "a"


def test_jspac():

    ctx = JSProxyAutoConfig(
        """
    function FindProxyForURL(url, host){
        if (isInNet("10.8.12.10", "10.8.12.1", "255.255.255.0")) {
            return "SOCKS "+host
        }else{
            return "DIRECT"
        }
    }

    """
    )
    assert ctx.FindProxyForURL("https://google.com", "google.com") == "SOCKS google.com"


if __name__ == "__main__":
    test_pac_convert_addr()
    test_pac_localHostOrDomainIs()
    test_jscontext()
