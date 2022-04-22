from typing import NamedTuple
from ._vendor.crypto import *


class _X509Credentials(NamedTuple):
    key: PrivateKey
    cert: Certificate
    chain: "list[Certificate]"

    @property
    def subject(self):
        return self.cert.subject

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.subject.rfc4514_string()})"


class _X509Identity(NamedTuple):
    cert: Certificate
    chain: "list[Certificate]"

    @property
    def subject(self):
        return self.cert.subject

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.subject.rfc4514_string()})"